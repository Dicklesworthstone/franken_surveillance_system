use std::error::Error;

use fss_core::{CanonicalEncode, ContentDigest};

use crate::{
    InMemoryObjectStore, ObjectError, ObjectLimits, ObjectManifest, ObjectState,
    VerifiedObjectCatalog,
};

#[test]
fn staged_bytes_are_not_readable_before_verification() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(8, 1024));
    let digest = store.stage(b"frame")?;
    assert_eq!(store.state(digest), Some(ObjectState::Staged));
    assert!(matches!(
        store.read_verified(digest),
        Err(ObjectError::NotVerified(found)) if found == digest
    ));
    store.verify(digest)?;
    assert_eq!(store.read_verified(digest)?, b"frame");
    Ok(())
}

#[test]
fn manifest_is_order_independent_and_root_last() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 4096));
    let first = store.put_verified(b"first-child")?;
    let second = store.put_verified(b"second-child")?;
    let manifest_a = ObjectManifest::new("event", [second, first, first], None)?;
    let manifest_b = ObjectManifest::new("event", [first, second], None)?;
    assert_eq!(manifest_a, manifest_b);
    assert_eq!(manifest_a.root(), manifest_b.root());
    assert_eq!(manifest_a.children(), &[first.min(second), first.max(second)]);

    let receipt = store.publish_manifest(manifest_a.clone())?;
    assert_eq!(receipt.root, manifest_a.root());
    assert_eq!(receipt.child_count, 2);
    assert_eq!(receipt.closure_object_count, 3);
    assert_eq!(store.published_manifest(receipt.root)?, &manifest_a);
    Ok(())
}

#[test]
fn missing_child_prevents_any_root_visibility() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(8, 4096));
    let missing = ContentDigest::sha256(b"not-staged");
    let manifest = ObjectManifest::new("event", [missing], None)?;
    let root = manifest.root();
    assert!(matches!(
        store.publish_manifest(manifest),
        Err(ObjectError::Missing(found)) if found == missing
    ));
    assert_eq!(store.published_manifest_count(), 0);
    assert!(matches!(
        store.published_manifest(root),
        Err(ObjectError::ManifestNotPublished(found)) if found == root
    ));
    Ok(())
}

#[test]
fn missing_metadata_object_prevents_root_visibility() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(8, 4096));
    let child = store.put_verified(b"child")?;
    let metadata = ContentDigest::sha256(b"metadata-not-staged");
    let manifest = ObjectManifest::new("event", [child], Some(metadata))?;
    assert!(manifest.children().contains(&metadata));
    let root = manifest.root();

    assert!(matches!(
        store.publish_manifest(manifest),
        Err(ObjectError::Missing(found)) if found == metadata
    ));
    assert_eq!(store.published_manifest_count(), 0);
    assert!(matches!(
        store.published_manifest(root),
        Err(ObjectError::ManifestNotPublished(found)) if found == root
    ));
    Ok(())
}

#[test]
fn byte_quota_failure_has_no_accounting_side_effect() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(4, 3));
    let first = store.stage(b"abc")?;
    assert_eq!(store.object_count(), 1);
    assert_eq!(store.total_bytes(), 3);
    assert!(matches!(
        store.stage(b"d"),
        Err(ObjectError::ByteQuotaExceeded {
            current: 3,
            requested: 1,
            maximum: 3
        })
    ));
    assert_eq!(store.object_count(), 1);
    assert_eq!(store.total_bytes(), 3);
    assert_eq!(store.state(first), Some(ObjectState::Staged));
    Ok(())
}

#[test]
fn verified_corruption_is_detected_on_read_and_closure() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(8, 4096));
    let child = store.put_verified(b"child")?;
    let manifest = ObjectManifest::new("event", [child], None)?;
    let root = store.publish_manifest(manifest)?.root;
    store.corrupt_for_test(child)?;
    assert!(matches!(
        store.read_verified(child),
        Err(ObjectError::Corrupt(found)) if found == child
    ));
    assert!(matches!(
        store.verify_closure(root),
        Err(ObjectError::Corrupt(found)) if found == child
    ));
    Ok(())
}

#[test]
fn nested_manifest_closure_includes_metadata_without_double_counting() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 8192));
    let leaf = store.put_verified(b"leaf")?;
    let metadata = store.put_verified(b"meta")?;
    let child_manifest = ObjectManifest::new("clip", [leaf], None)?;
    let child_root = store.publish_manifest(child_manifest)?.root;
    let root_manifest = ObjectManifest::new("incident", [leaf, child_root], Some(metadata))?;
    assert_eq!(root_manifest.children().len(), 3);
    let root = store.publish_manifest(root_manifest)?.root;
    assert_eq!(store.verify_closure(root)?, 4);
    store.require_verified(root)?;
    Ok(())
}

#[test]
fn canonical_manifest_bytes_bind_kind_children_and_metadata() -> Result<(), Box<dyn Error>> {
    let child = ContentDigest::sha256(b"child");
    let metadata = ContentDigest::sha256(b"meta");
    let first = ObjectManifest::new("event", [child], None)?;
    let second = ObjectManifest::new("clip", [child], None)?;
    let third = ObjectManifest::new("event", [child], Some(metadata))?;
    assert_ne!(first.canonical_bytes(), second.canonical_bytes());
    assert_ne!(first.root(), second.root());
    assert_ne!(first.root(), third.root());
    assert!(third.children().contains(&metadata));
    Ok(())
}
