#![forbid(unsafe_code)]
//! Integration tests demonstrating and proving defects in fss-object.

use std::error::Error;

use fss_core::{CanonicalEncode, ContentDigest};
use fss_object::{InMemoryObjectStore, MAX_MANIFEST_CHILDREN, ObjectLimits, ObjectManifest};

/// F2: Sub-manifests must be published bottom-up. When a sub-manifest is published in
/// visible_manifests, parent manifest publication descends into the sub-manifest closure
/// and verifies all reachable leaves. If a leaf in the sub-manifest is missing or corrupt,
/// parent publication fails.
#[test]
fn sub_manifests_must_be_published_bottom_up_and_closure_verified() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 8192));
    let leaf = store.put_verified(b"leaf-content")?;

    // Child manifest published bottom-up first:
    let child_manifest = ObjectManifest::new("clip", [leaf], None)?;
    let child_receipt = store.publish_manifest(child_manifest.clone())?;
    if child_receipt.closure_object_count != 2 {
        return Err("expected child manifest closure to have 2 objects (child + leaf)".into());
    }

    // Corrupt leaf in child manifest:
    store.corrupt_for_test(leaf)?;

    // Parent manifest referencing child manifest:
    let parent_manifest = ObjectManifest::new("incident", [child_manifest.root()], None)?;
    let publish_result = store.publish_manifest(parent_manifest);
    if publish_result.is_ok() {
        return Err(
            "expected parent publication to fail because child manifest's leaf is corrupt".into(),
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

/// PinkCoast finding 1: An opaque leaf whose payload bytes happen to parse as an ObjectManifest
/// must NOT cause closure descent. It is an opaque leaf because it is not in visible_manifests.
#[test]
fn opaque_leaf_shaped_like_manifest_does_not_cause_closure_descent() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 8192));
    let non_existent_digest = ContentDigest::sha256(b"does-not-exist-in-store");

    // Construct a payload whose serialized bytes happen to parse as an ObjectManifest:
    let fake_manifest = ObjectManifest::new("clip", [non_existent_digest], None)?;
    let leaf_bytes = fake_manifest.canonical_bytes();

    // Store this payload as an opaque verified leaf object:
    let leaf_digest = store.put_verified(&leaf_bytes)?;

    // A valid parent manifest references the opaque leaf object:
    let parent_manifest = ObjectManifest::new("incident", [leaf_digest], None)?;

    // Publication MUST succeed because leaf_digest is verified and present in store,
    // and opaque leaves are not trial-parsed as manifests.
    let receipt = store.publish_manifest(parent_manifest)?;
    assert_eq!(receipt.closure_object_count, 2);
    Ok(())
}

/// PinkCoast finding 3: Pre-existing Staged object must not remain promoted to Verified
/// when publish_manifest fails.
#[test]
fn pre_existing_staged_object_is_not_promoted_to_verified_on_publish_failure()
-> Result<(), Box<dyn Error>> {
    use fss_object::ObjectState;

    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 8192));
    let leaf = store.put_verified(b"leaf-1")?;

    // Create a child manifest, published so it is in visible_manifests:
    let child_manifest = ObjectManifest::new("clip", [leaf], None)?;
    store.publish_manifest(child_manifest.clone())?;

    // Corrupt leaf so closure verification of parent will fail:
    store.corrupt_for_test(leaf)?;

    // Parent manifest referencing child_manifest:
    let parent_manifest = ObjectManifest::new("incident", [child_manifest.root()], None)?;
    let parent_root = parent_manifest.root();
    let parent_bytes = parent_manifest.canonical_bytes();

    // Stage parent bytes in advance so it exists in ObjectState::Staged:
    store.stage(&parent_bytes)?;
    assert_eq!(store.state(parent_root), Some(ObjectState::Staged));

    // publish_manifest should fail because leaf is corrupt:
    let res = store.publish_manifest(parent_manifest);
    assert!(res.is_err());

    // Invariant: The pre-existing staged parent manifest must NOT remain in ObjectState::Verified!
    // It must be restored to ObjectState::Staged.
    if store.state(parent_root) != Some(ObjectState::Staged) {
        return Err(
            "pre-existing staged object was left promoted to Verified after publish failure".into(),
        );
    }

    Ok(())
}
