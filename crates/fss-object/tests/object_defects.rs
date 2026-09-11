#![forbid(unsafe_code)]
//! Integration tests demonstrating and proving defects in fss-object.

use std::error::Error;

use fss_core::{CanonicalEncode, ContentDigest};
use fss_object::{InMemoryObjectStore, MAX_MANIFEST_CHILDREN, ObjectLimits, ObjectManifest};

/// F2: verify_closure must descend into manifest-shaped child objects even if they
/// were only put via put_verified and not published in visible_manifests.
#[test]
fn sub_manifest_missing_leaf_must_prevent_parent_manifest_publication() -> Result<(), Box<dyn Error>>
{
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 8192));
    let missing_leaf = ContentDigest::sha256(b"missing-leaf-object");

    // Construct a child manifest referencing missing_leaf:
    let child_manifest = ObjectManifest::new("clip", [missing_leaf], None)?;
    let child_root = child_manifest.root();

    // Stage and verify the child manifest bytes as an opaque object, but DO NOT publish it:
    store.put_verified(&child_manifest.canonical_bytes())?;

    // Parent manifest references the child manifest root:
    let parent_manifest = ObjectManifest::new("incident", [child_root], None)?;

    let publish_result = store.publish_manifest(parent_manifest);
    if publish_result.is_ok() {
        return Err(
            "F2 defect confirmed: parent manifest published despite sub-manifest missing leaf"
                .into(),
        );
    }

    Ok(())
}

/// F3: ObjectManifest::new must reject duplicate children with a typed error,
/// and the MAX_MANIFEST_CHILDREN bound must apply to input length before dedup.
#[test]
fn duplicate_children_must_be_rejected_and_bound_applies_to_input() -> Result<(), Box<dyn Error>> {
    let child = ContentDigest::sha256(b"child-1");

    // Test A: Duplicate child digests should be rejected:
    let duplicate_result = ObjectManifest::new("event", [child, child], None);
    if duplicate_result.is_ok() {
        return Err("F3 defect confirmed: duplicate children silently accepted via dedup".into());
    }

    // Test B: Input with MAX_MANIFEST_CHILDREN + 1 elements with duplicates
    // must not bypass the child bound via dedup:
    let oversized = vec![child; MAX_MANIFEST_CHILDREN + 1];
    let bound_result = ObjectManifest::new("event", oversized, None);
    if bound_result.is_ok() {
        return Err(
            "F3 defect confirmed: oversized input bypassed MAX_MANIFEST_CHILDREN via dedup".into(),
        );
    }

    // Test C: metadata_digest that duplicates an element in children must also be rejected:
    let metadata_dup = ObjectManifest::new("event", [child], Some(child));
    if metadata_dup.is_ok() {
        return Err("F3 defect confirmed: metadata_digest duplicate silently accepted".into());
    }

    Ok(())
}

/// F4: A 0-byte quota (max_total_bytes == 0) must reject any object admission, including 0-byte objects.
#[test]
fn zero_byte_quota_must_reject_object_admission() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(10, 0));
    let stage_result = store.stage(b"");
    if stage_result.is_ok() {
        return Err(
            "F4 defect confirmed: 0-byte object admitted under max_total_bytes == 0 quota".into(),
        );
    }

    Ok(())
}

/// F5: published_manifest must re-verify the stored object digest on lookup.
#[test]
fn published_manifest_must_verify_digest_on_lookup() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(8, 4096));
    let child = store.put_verified(b"child-bytes")?;
    let manifest = ObjectManifest::new("event", [child], None)?;
    let receipt = store.publish_manifest(manifest)?;
    let root = receipt.root;

    // Corrupt the manifest object's bytes in the store:
    store.corrupt_for_test(root)?;

    // published_manifest must detect corruption and return Err(ObjectError::Corrupt):
    let lookup_result = store.published_manifest(root);
    if lookup_result.is_ok() {
        return Err(
            "F5 defect confirmed: published_manifest skipped digest verification on cache hit"
                .into(),
        );
    }

    Ok(())
}

/// F7: When publish_manifest fails during verify_closure, no staged object or quota may be leaked.
#[test]
fn failed_manifest_publication_must_not_leak_staged_object_or_quota() -> Result<(), Box<dyn Error>>
{
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 8192));
    let leaf = store.put_verified(b"leaf-bytes")?;
    let sub_manifest = ObjectManifest::new("clip", [leaf], None)?;
    let sub_root = store.publish_manifest(sub_manifest)?.root;

    let initial_objects = store.object_count(); // leaf + sub_manifest = 2
    let initial_bytes = store.total_bytes();

    let parent_manifest = ObjectManifest::new("incident", [sub_root], None)?;
    let parent_root = parent_manifest.root();

    // Corrupt leaf so that direct children of parent_manifest (sub_root) pass require_all_verified,
    // but verify_closure will fail on the grandchild leaf:
    store.corrupt_for_test(leaf)?;

    let publish_result = store.publish_manifest(parent_manifest);
    if publish_result.is_ok() {
        return Err("expected publish_manifest to fail due to corrupt grandchild leaf".into());
    }

    // Check if the parent manifest object leaked in objects:
    if store.object_count() != initial_objects {
        return Err(format!(
            "F7 defect confirmed: object_count leaked: expected {initial_objects}, got {}",
            store.object_count()
        )
        .into());
    }

    if store.total_bytes() != initial_bytes {
        return Err(format!(
            "F7 defect confirmed: total_bytes leaked quota: expected {initial_bytes}, got {}",
            store.total_bytes()
        )
        .into());
    }

    if store.state(parent_root).is_some() {
        return Err(
            "F7 defect confirmed: parent manifest root object still present in store".into(),
        );
    }

    Ok(())
}
