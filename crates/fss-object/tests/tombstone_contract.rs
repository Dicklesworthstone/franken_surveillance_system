#![forbid(unsafe_code)]
//! Integration tests verifying the immutable object tombstone contract (OBJECT-TOMBSTONE-001).

use std::error::Error;

use fss_core::{ContentDigest, Generation, ObjectId, TombstoneReason, TombstoneRecord};
use fss_object::{InMemoryObjectStore, ObjectError, ObjectLimits, ObjectManifest, ObjectState};

fn sample_tombstone(
    id_str: &str,
    prior_gen: u64,
    payload_digest: ContentDigest,
) -> Result<TombstoneRecord, Box<dyn Error>> {
    let id = ObjectId::parse(id_str)?;
    let prior = Generation::parse_positive(prior_gen)?;
    let tombstone_gen = prior.next()?;
    let record = TombstoneRecord::new(
        id,
        tombstone_gen,
        prior,
        TombstoneReason::Deleted,
        None,
        payload_digest,
    )?;
    Ok(record)
}

/// Positive: InMemoryObjectStore::tombstone moves a Verified object to Tombstoned,
/// retains the record and digest, releases payload bytes and quota.
#[test]
fn verified_object_transitions_to_tombstoned_and_releases_bytes_and_quota()
-> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 4096));
    let payload = b"sensitive-surveillance-evidence";
    let digest = store.put_verified(payload)?;

    assert_eq!(store.object_count(), 1);
    assert_eq!(store.total_bytes(), payload.len() as u64);
    assert_eq!(store.state(digest), Some(ObjectState::Verified));
    assert_eq!(store.read_verified(digest)?, payload);

    let record = sample_tombstone("obj-evidence-001", 1, digest)?;
    store.tombstone(digest, record.clone())?;

    // Digest and record remain tracked:
    assert_eq!(store.object_count(), 1);
    assert_eq!(store.state(digest), Some(ObjectState::Tombstoned));
    assert!(store.is_tombstoned(digest));
    assert_eq!(store.tombstone_record(digest), Some(&record));

    // Payload bytes and quota are released:
    assert_eq!(store.total_bytes(), 0);

    // read_verified returns typed Tombstoned error:
    let read_result = store.read_verified(digest);
    assert!(matches!(read_result, Err(ObjectError::Tombstoned(d)) if d == digest));

    Ok(())
}

/// Positive: publish_manifest fails when referencing a tombstoned child,
/// and verify_closure fails when an already-published manifest has a child tombstoned.
#[test]
fn publish_and_closure_verification_fail_naming_tombstoned_child() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 8192));
    let child_a = store.put_verified(b"child-a")?;
    let child_b = store.put_verified(b"child-b")?;

    // Tombstone child_a before publishing:
    let record_a = sample_tombstone("obj-child-a", 1, child_a)?;
    store.tombstone(child_a, record_a)?;

    // Attempting to publish manifest referencing child_a must fail naming child_a:
    let manifest = ObjectManifest::new("incident", [child_a, child_b], None)?;
    let pub_result = store.publish_manifest(manifest);
    assert!(matches!(pub_result, Err(ObjectError::Tombstoned(d)) if d == child_a));

    // Now publish a valid manifest referencing only child_b:
    let valid_manifest = ObjectManifest::new("incident-valid", [child_b], None)?;
    let receipt = store.publish_manifest(valid_manifest)?;
    assert_eq!(store.verify_closure(receipt.root)?, 2);

    // Later, child_b is tombstoned:
    let record_b = sample_tombstone("obj-child-b", 1, child_b)?;
    store.tombstone(child_b, record_b)?;

    // verify_closure must now fail naming child_b:
    let verify_result = store.verify_closure(receipt.root);
    assert!(matches!(verify_result, Err(ObjectError::Tombstoned(d)) if d == child_b));

    Ok(())
}

/// Positive: published manifests whose closure contains a tombstoned child
/// are reported by published_manifests_with_tombstoned_closure.
#[test]
fn closure_query_reports_manifests_with_tombstoned_descendants() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(32, 16384));
    let leaf_1 = store.put_verified(b"leaf-1")?;
    let leaf_2 = store.put_verified(b"leaf-2")?;

    // Sub-manifest referencing leaf_1:
    let sub_manifest = ObjectManifest::new("clip", [leaf_1], None)?;
    let sub_root = store.publish_manifest(sub_manifest)?.root;

    // Parent manifest referencing sub_root and leaf_2:
    let parent_manifest = ObjectManifest::new("incident", [sub_root, leaf_2], None)?;
    let parent_root = store.publish_manifest(parent_manifest)?.root;

    // Independent manifest referencing only leaf_2:
    let clean_manifest = ObjectManifest::new("unrelated", [leaf_2], None)?;
    let clean_root = store.publish_manifest(clean_manifest)?.root;

    // Initially no manifest has any tombstone in closure:
    assert!(
        store
            .published_manifests_with_tombstoned_closure()
            .is_empty()
    );
    assert!(!store.closure_contains_tombstone(sub_root));
    assert!(!store.closure_contains_tombstone(parent_root));
    assert!(!store.closure_contains_tombstone(clean_root));

    // Tombstone leaf_1:
    let record = sample_tombstone("obj-leaf-1", 1, leaf_1)?;
    store.tombstone(leaf_1, record)?;

    // Both sub_root and parent_root now have a tombstone in their closure:
    assert!(store.closure_contains_tombstone(sub_root));
    assert!(store.closure_contains_tombstone(parent_root));
    assert!(!store.closure_contains_tombstone(clean_root));

    let reported = store.published_manifests_with_tombstoned_closure();
    let expected = if sub_root < parent_root {
        vec![sub_root, parent_root]
    } else {
        vec![parent_root, sub_root]
    };
    assert_eq!(reported, expected);

    // Alias methods return identical results:
    assert_eq!(store.manifests_with_tombstoned_closure(), expected);
    assert_eq!(
        store.published_manifests_with_tombstoned_children(),
        expected
    );

    Ok(())
}

/// Planted Negative: Tombstoning an unknown or staged object is refused.
#[test]
fn tombstoning_unknown_or_staged_object_is_refused() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 4096));

    // Case 1: Unknown object
    let unknown_digest = ContentDigest::sha256(b"not-present");
    let record_unknown = sample_tombstone("obj-unknown", 1, unknown_digest)?;
    let unknown_res = store.tombstone(unknown_digest, record_unknown);
    assert!(matches!(unknown_res, Err(ObjectError::Missing(d)) if d == unknown_digest));

    // Case 2: Staged object (not verified)
    let staged_digest = store.stage(b"staged-only")?;
    assert_eq!(store.state(staged_digest), Some(ObjectState::Staged));
    let record_staged = sample_tombstone("obj-staged", 1, staged_digest)?;
    let staged_res = store.tombstone(staged_digest, record_staged);
    assert!(matches!(staged_res, Err(ObjectError::NotVerified(d)) if d == staged_digest));

    // State of staged object remains Staged:
    assert_eq!(store.state(staged_digest), Some(ObjectState::Staged));

    Ok(())
}

/// Planted Negative: A tombstone whose record digest does not match the object is refused.
#[test]
fn tombstone_record_digest_mismatch_is_refused() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 4096));
    let digest = store.put_verified(b"real-content")?;
    let wrong_digest = ContentDigest::sha256(b"wrong-content");

    let mismatched_record = sample_tombstone("obj-mismatch", 1, wrong_digest)?;
    let res = store.tombstone(digest, mismatched_record);
    assert!(matches!(
        res,
        Err(ObjectError::TombstoneDigestMismatch { expected, actual })
            if expected == digest && actual == wrong_digest
    ));

    // Object remains Verified and readable:
    assert_eq!(store.state(digest), Some(ObjectState::Verified));
    assert_eq!(store.read_verified(digest)?, b"real-content");

    Ok(())
}

/// Planted Negative: Re-putting or restaging the same bytes after tombstone does not resurrect it.
#[test]
fn re_putting_same_bytes_after_tombstone_does_not_resurrect() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 4096));
    let bytes = b"immutable-deletion-target";
    let digest = store.put_verified(bytes)?;

    let record = sample_tombstone("obj-resurrect-target", 1, digest)?;
    store.tombstone(digest, record)?;

    // Attempt to stage identical bytes:
    let stage_res = store.stage(bytes);
    assert!(matches!(stage_res, Err(ObjectError::Tombstoned(d)) if d == digest));

    // Attempt to put_verified identical bytes:
    let put_res = store.put_verified(bytes);
    assert!(matches!(put_res, Err(ObjectError::Tombstoned(d)) if d == digest));

    // Attempt to verify directly:
    let verify_res = store.verify(digest);
    assert!(matches!(verify_res, Err(ObjectError::Tombstoned(d)) if d == digest));

    // State remains Tombstoned:
    assert_eq!(store.state(digest), Some(ObjectState::Tombstoned));
    assert_eq!(store.total_bytes(), 0);

    Ok(())
}

/// Planted Negative: Tombstone is idempotent for an identical record,
/// but conflicting records are rejected with TombstoneConflict.
#[test]
fn tombstone_is_idempotent_for_identical_record_and_rejects_conflict() -> Result<(), Box<dyn Error>>
{
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 4096));
    let bytes = b"idempotent-test-bytes";
    let digest = store.put_verified(bytes)?;

    let record = sample_tombstone("obj-idempotent", 1, digest)?;
    store.tombstone(digest, record.clone())?;

    let bytes_after_first = store.total_bytes();
    assert_eq!(bytes_after_first, 0);

    // Second call with identical record succeeds idempotently:
    store.tombstone(digest, record.clone())?;
    assert_eq!(store.total_bytes(), 0);
    assert_eq!(store.object_count(), 1);
    assert_eq!(store.state(digest), Some(ObjectState::Tombstoned));

    // Third call with conflicting record (different generation and reason):
    let conflicting_record = TombstoneRecord::new(
        ObjectId::parse("obj-idempotent")?,
        Generation::parse_positive(3)?,
        Generation::parse_positive(2)?,
        TombstoneReason::Expired,
        None,
        digest,
    )?;
    let conflict_res = store.tombstone(digest, conflicting_record);
    assert!(matches!(conflict_res, Err(ObjectError::TombstoneConflict(d)) if d == digest));

    Ok(())
}
