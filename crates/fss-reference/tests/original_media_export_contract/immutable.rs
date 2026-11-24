#![forbid(unsafe_code)]
//! The original media owner verifies the same native proof through immutable retained custody.

use super::*;
use std::collections::BTreeMap;
use std::path::Path;

use fss_reference::agent_orient::OrientLimits;
use fss_reference::retained_source::{
    ImmutableRetainedReadLimits, ImmutableRetainedSource, RetainedReadUsage,
};

fn limits() -> ImmutableRetainedReadLimits {
    ImmutableRetainedReadLimits {
        snapshot: OrientLimits::default(),
        max_read_bytes: 1024 * 1024 * 1024,
        max_read_objects: 1_000_000,
    }
}

fn tree(root: &Path) -> Test<BTreeMap<PathBuf, ContentDigest>> {
    fn walk(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, ContentDigest>) -> Test {
        for item in fs::read_dir(path)? {
            let item = item?;
            if item.file_type()?.is_dir() {
                out.insert(
                    item.path().strip_prefix(root)?.to_path_buf(),
                    ContentDigest::sha256(b"directory"),
                );
                walk(root, &item.path(), out)?;
            } else {
                out.insert(
                    item.path().strip_prefix(root)?.to_path_buf(),
                    ContentDigest::sha256(&fs::read(item.path())?),
                );
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out)?;
    Ok(out)
}

fn read(f: &Fixture, limits: ImmutableRetainedReadLimits) -> Test<RetainedReadUsage> {
    let root = f.deployment.root();
    let cx = ReplayCx::from_context_authority_read_only(&f.authority, root.to_path_buf())?;
    let source = ImmutableRetainedSource::open(root, limits, &cx)?;
    let preview = preview_original_media_export(&source, &f.request, &f.authority, &cx)?;
    assert_eq!(preview.media_bytes(), f.source);
    source.revalidate_snapshot_metadata()?;
    source.revalidate()?;
    Ok(source.usage())
}

#[test]
fn immutable_native_and_reviewed_media_match_exactly_while_writer_is_held() -> Test {
    let mut f = Fixture::new("immutable-parity")?;
    for reviewed in [false, true] {
        if reviewed {
            let request = ReviewRequest {
                event_id: f.request.event.event_id.clone(),
                expected_revision: f.request.event.expected_revision,
                disposition: ReviewDisposition::Investigate,
                reason: "private review text stays outside the exported record".into(),
            };
            let prepared = preview_review(&f.deployment, &request, &f.authority, &f.cx)?;
            let committed = commit_review(
                &mut f.deployment,
                &request,
                prepared.approval(),
                &f.authority,
                &f.cx,
            )?;
            f.request.event.expected_revision = committed.review.event().revision_digest();
        }
        let before = tree(f.deployment.root())?;
        let expected =
            preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx)?;
        let cx = ReplayCx::from_context_authority_read_only(
            &f.authority,
            f.deployment.root().to_path_buf(),
        )?;
        let source = ImmutableRetainedSource::open(f.deployment.root(), limits(), &cx)?;
        let actual = preview_original_media_export(&source, &f.request, &f.authority, &cx)?;
        assert_eq!(actual.record_bytes(), expected.record_bytes());
        assert_eq!(actual.manifest_bytes(), expected.manifest_bytes());
        assert_eq!(actual.media_bytes(), expected.media_bytes());
        assert_eq!(actual.record_json(), expected.record_json());
        assert_eq!(actual.approval(), expected.approval());
        assert_eq!(actual.root(), expected.root());
        source.revalidate_snapshot_metadata()?;
        source.revalidate()?;
        assert_eq!(tree(f.deployment.root())?, before);
    }
    Ok(())
}

#[test]
fn immutable_package_and_reviewed_package_media_preserve_native_custody() -> Test {
    let mut f = package::fixture("immutable-package")?;
    for reviewed in [false, true] {
        if reviewed {
            let request = ReviewRequest {
                event_id: f.request.event.event_id.clone(),
                expected_revision: f.request.event.expected_revision,
                disposition: ReviewDisposition::Resolve,
                reason: "operator-only package resolution".into(),
            };
            let prepared = preview_review(&f.deployment, &request, &f.authority, &f.cx)?;
            let committed = commit_review(
                &mut f.deployment,
                &request,
                prepared.approval(),
                &f.authority,
                &f.cx,
            )?;
            f.request.event.expected_revision = committed.review.event().revision_digest();
        }
        let expected =
            preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx)?;
        let cx = ReplayCx::from_context_authority_read_only(
            &f.authority,
            f.deployment.root().to_path_buf(),
        )?;
        let source = ImmutableRetainedSource::open(f.deployment.root(), limits(), &cx)?;
        let actual = preview_original_media_export(&source, &f.request, &f.authority, &cx)?;
        assert_eq!(actual.record_bytes(), expected.record_bytes());
        assert_eq!(actual.approval(), expected.approval());
        assert_eq!(actual.media_bytes(), f.source);
        source.revalidate_snapshot_metadata()?;
        source.revalidate()?;
    }
    Ok(())
}

#[test]
fn immutable_media_uses_one_exact_allowance_through_final_validation() -> Test {
    let f = Fixture::new("immutable-budget")?;
    let measured = read(&f, limits())?;
    let exact = ImmutableRetainedReadLimits {
        max_read_bytes: usize::try_from(measured.read_bytes)?,
        max_read_objects: usize::try_from(measured.read_objects)?,
        ..limits()
    };
    assert_eq!(read(&f, exact)?, measured);
    assert!(
        read(
            &f,
            ImmutableRetainedReadLimits {
                max_read_bytes: exact.max_read_bytes - 1,
                ..exact
            }
        )
        .is_err()
    );
    assert!(
        read(
            &f,
            ImmutableRetainedReadLimits {
                max_read_objects: exact.max_read_objects - 1,
                ..exact
            }
        )
        .is_err()
    );

    let cx = ReplayCx::from_context_authority_read_only(
        &f.authority,
        f.deployment.root().to_path_buf(),
    )?;
    let source = ImmutableRetainedSource::open(f.deployment.root(), limits(), &cx)?;
    let _ = preview_original_media_export(&source, &f.request, &f.authority, &cx)?;
    let before_final = source.usage();
    assert!(before_final.read_bytes < measured.read_bytes);
    assert!(before_final.read_objects < measured.read_objects);
    let limited = ImmutableRetainedSource::open(
        f.deployment.root(),
        ImmutableRetainedReadLimits {
            max_read_bytes: usize::try_from(before_final.read_bytes)?,
            max_read_objects: usize::try_from(before_final.read_objects)?,
            ..limits()
        },
        &cx,
    )?;
    let _ = preview_original_media_export(&limited, &f.request, &f.authority, &cx)?;
    assert!(limited.revalidate_snapshot_metadata().is_err());
    assert!(limited.revalidate().is_err());
    Ok(())
}

#[test]
#[allow(clippy::result_large_err)]
fn immutable_media_final_validation_refuses_late_source_and_metadata_damage() -> Test {
    let f = Fixture::new("immutable-damage")?;
    let retained = RetainedFileImport::open(
        &f.deployment,
        f.request.import_identity,
        Default::default(),
        &f.cx,
    )?;
    let source_chunk = *retained
        .manifest()
        .ordered_chunks
        .last()
        .ok_or("source chunk")?;
    let (_, event_receipt) = f
        .deployment
        .current_event_authority(&f.request.event.event_id)?;
    for digest in [
        source_chunk,
        retained.manifest_digest(),
        event_receipt.event_object_digest,
        event_receipt.event_root,
    ] {
        let path = f.deployment.publisher().spool().object_path(digest);
        let original = fs::read(&path)?;
        let cx = ReplayCx::from_context_authority_read_only(
            &f.authority,
            f.deployment.root().to_path_buf(),
        )?;
        let source = ImmutableRetainedSource::open(f.deployment.root(), limits(), &cx)?;
        let _ = preview_original_media_export(&source, &f.request, &f.authority, &cx)?;
        let mut damaged = original.clone();
        *damaged.last_mut().ok_or("nonempty retained payload")? ^= 1;
        fs::write(&path, damaged)?;
        let damaged_tree = tree(f.deployment.root())?;
        assert!(
            source
                .revalidate_snapshot_metadata()
                .and_then(|()| source.revalidate())
                .is_err()
        );
        assert_eq!(tree(f.deployment.root())?, damaged_tree);
        fs::write(path, original)?;
    }
    Ok(())
}

#[test]
fn immutable_media_refuses_privacy_drift_and_cancelled_final_reads() -> Test {
    let mut f = Fixture::new("immutable-drift")?;
    let root = f.deployment.root().to_path_buf();
    let cx = ReplayCx::from_context_authority_read_only(&f.authority, root.clone())?;
    let source = ImmutableRetainedSource::open(&root, limits(), &cx)?;
    let _ = preview_original_media_export(&source, &f.request, &f.authority, &cx)?;
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:original-media")?,
        [48, 32],
        &[[40, 0, 8, 32]],
    )?;
    let approval = preview_mask(&f.deployment, &policy)?.approval;
    declare_mask(&mut f.deployment, &policy, approval, &f.cx)?;
    let changed = tree(&root)?;
    assert!(source.revalidate().is_err());
    assert_eq!(tree(&root)?, changed);

    let f = Fixture::new("immutable-final-cancel")?;
    let cx = ReplayCx::from_context_authority_read_only(
        &f.authority,
        f.deployment.root().to_path_buf(),
    )?;
    let source = ImmutableRetainedSource::open(f.deployment.root(), limits(), &cx)?;
    let _ = preview_original_media_export(&source, &f.request, &f.authority, &cx)?;
    let before = tree(f.deployment.root())?;
    cx.set_cancel_at_checkpoint("retained_source:read");
    assert!(source.revalidate_snapshot_metadata().is_err());
    assert_eq!(tree(f.deployment.root())?, before);
    Ok(())
}
