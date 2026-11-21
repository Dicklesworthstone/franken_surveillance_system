#![forbid(unsafe_code)]
//! Portable package preparation against immutable custody while capture owns the writer.

use super::*;
use crate::agent_orient::OrientLimits;
use crate::retained_source::{ImmutableRetainedReadLimits, ImmutableRetainedSource};
use fss_core::{Generation, TombstoneReason, TombstoneRecord};

fn limits() -> ImmutableRetainedReadLimits {
    ImmutableRetainedReadLimits {
        snapshot: OrientLimits::default(),
        max_read_bytes: 64 * 1024 * 1024,
        max_read_objects: 65_536,
    }
}

#[test]
fn immutable_and_native_packages_are_identical_without_original_media_or_models() -> Test {
    let mut fixture = Fixture::new("immutable-exact", 100)?;
    let root = fixture.commit()?;
    let expected = fixture.package(root)?;
    let read_cx =
        ReplayCx::from_context_authority_read_only(&fixture.auth, fixture.deployment.root())?;
    for payload in [
        b"private raw payload sentinel".as_slice(),
        b"private model payload sentinel",
    ] {
        fs::remove_file(
            fixture
                .deployment
                .publisher()
                .spool()
                .object_path(ContentDigest::sha256(payload)),
        )?;
    }
    let before = fixture.snapshot()?;
    let source = ImmutableRetainedSource::open(fixture.deployment.root(), limits(), &read_cx)?;
    let actual = prepare_package(&source, root, &scope(30, 40)?, &fixture.auth, &read_cx)?;
    source.revalidate_snapshot_metadata()?;
    source.revalidate()?;
    assert_eq!(actual, expected);
    assert_eq!(fixture.snapshot()?, before);
    read_cx.drain_and_finalize();
    Ok(())
}

#[test]
fn buffered_package_is_refused_after_manifest_record_or_publication_corruption() -> Test {
    for kind in ["manifest", "record", "publication"] {
        let mut fixture = Fixture::new(&format!("immutable-{kind}"), 100)?;
        let root = fixture.commit()?;
        let read_cx =
            ReplayCx::from_context_authority_read_only(&fixture.auth, fixture.deployment.root())?;
        let source = ImmutableRetainedSource::open(fixture.deployment.root(), limits(), &read_cx)?;
        let package = prepare_package(&source, root, &scope(30, 40)?, &fixture.auth, &read_cx)?;
        let record = package.verified().record();
        let path = match kind {
            "manifest" => fixture.deployment.publisher().spool().object_path(root),
            "record" => fixture
                .deployment
                .publisher()
                .spool()
                .object_path(record.digest()),
            _ => fixture
                .deployment
                .publisher()
                .root_dir()
                .join("roots")
                .join(format!("{}.root", record.slot()?)),
        };
        let mut corrupted = fs::read(&path)?;
        let last = corrupted.last_mut().ok_or("empty custody record")?;
        *last ^= 1;
        fs::write(&path, &corrupted)?;
        let before = fixture.snapshot()?;
        let final_check = source
            .revalidate_snapshot_metadata()
            .and_then(|()| source.revalidate());
        assert!(final_check.is_err(), "accepted changed {kind}");
        assert_eq!(fs::read(path)?, corrupted, "repaired changed {kind}");
        assert_eq!(fixture.snapshot()?, before);
        read_cx.drain_and_finalize();
    }
    Ok(())
}

#[test]
fn late_tombstone_refuses_buffered_package_even_while_payload_bytes_remain() -> Test {
    let mut fixture = Fixture::new("immutable-tombstone", 100)?;
    let root = fixture.commit()?;
    let read_cx =
        ReplayCx::from_context_authority_read_only(&fixture.auth, fixture.deployment.root())?;
    let source = ImmutableRetainedSource::open(fixture.deployment.root(), limits(), &read_cx)?;
    let package = prepare_package(&source, root, &scope(30, 40)?, &fixture.auth, &read_cx)?;
    let record = package.verified().record();
    let digest = record.digest();
    let path = fixture
        .deployment
        .publisher()
        .root_dir()
        .join("tombstones")
        .join(format!("{}.tomb", digest.to_text().replacen(':', "-", 1)));
    // Inject a retained revocation record after preparation, without changing either journal.
    // This models a concurrent custody invalidator; its bytes must not be silently repaired.
    let tombstone = TombstoneRecord::new(
        ObjectId::parse(format!(
            "{EXPORT_OBJECT_PREFIX}{}",
            digest.to_text().trim_start_matches("sha256:")
        ))?,
        Generation(2),
        Generation(1),
        TombstoneReason::Deleted,
        Some(ContentDigest::sha256(b"concurrent deletion witness")),
        digest,
    )?;
    fs::write(&path, fss_publication::tombstone_record_bytes(&tombstone)?)?;
    let before = fixture.snapshot()?;
    assert!(
        fixture
            .deployment
            .publisher()
            .spool()
            .object_path(digest)
            .exists()
    );
    assert!(source.revalidate().is_err());
    assert!(path.exists());
    assert_eq!(fixture.snapshot()?, before);
    read_cx.drain_and_finalize();
    Ok(())
}

#[test]
fn final_revalidation_refuses_late_journal_tail_and_cancellation_without_recovery() -> Test {
    for kind in ["ledger/journal.fssj", "effects/journal.fssj", "cancel"] {
        let mut fixture =
            Fixture::new(&format!("immutable-final-{}", kind.replace('/', "-")), 100)?;
        let root = fixture.commit()?;
        let read_cx =
            ReplayCx::from_context_authority_read_only(&fixture.auth, fixture.deployment.root())?;
        let source = ImmutableRetainedSource::open(fixture.deployment.root(), limits(), &read_cx)?;
        let _buffered = prepare_package(&source, root, &scope(30, 40)?, &fixture.auth, &read_cx)?;
        source.revalidate_snapshot_metadata()?;
        if kind == "cancel" {
            read_cx.set_cancel_at_checkpoint("retained_source:read");
        } else {
            let path = fixture.deployment.root().join(kind);
            let mut bytes = fs::read(&path)?;
            bytes.extend_from_slice(b"FSS");
            fs::write(path, bytes)?;
        }
        let before = fixture.snapshot()?;
        let error = source
            .revalidate()
            .err()
            .ok_or("accepted a final invalidation")?;
        if kind == "cancel" {
            assert!(matches!(
                error,
                FileIngestError::CancellationRequested { .. }
            ));
        }
        assert_eq!(fixture.snapshot()?, before);
        read_cx.drain_and_finalize();
    }
    Ok(())
}
