#![forbid(unsafe_code)]
//! Integration tests verifying the immutable object tombstone contract (OBJECT-TOMBSTONE-001).

use std::error::Error;

use fss_core::{ContentDigest, Generation, ObjectId, TombstoneReason, TombstoneRecord};
use fss_object::{InMemoryObjectStore, ObjectError, ObjectLimits, ObjectManifest, ObjectState};

fn sample_tombstone(
    id_str: &str,
    prior_gen: u64,
    payload_digest: ContentDigest,
    witness_digest: Option<ContentDigest>,
) -> Result<TombstoneRecord, Box<dyn Error>> {
    let id = ObjectId::parse(id_str)?;
    let prior = Generation::parse_positive(prior_gen)?;
    let tombstone_gen = prior.next()?;
    let record = TombstoneRecord::new(
        id,
        tombstone_gen,
        prior,
        TombstoneReason::Deleted,
        witness_digest,
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
    let witness = store.put_verified(b"deletion-witness-001")?;

    assert_eq!(store.object_count(), 2);
    assert_eq!(
        store.total_bytes(),
        payload.len() as u64 + b"deletion-witness-001".len() as u64
    );
    assert_eq!(store.state(digest), Some(ObjectState::Verified));
    assert_eq!(store.read_verified(digest)?, payload);

    let record = sample_tombstone("obj-evidence-001", 1, digest, Some(witness))?;
    store.tombstone(digest, record.clone())?;

    // Digest and record remain tracked:
    assert_eq!(store.object_count(), 2);
    assert_eq!(store.state(digest), Some(ObjectState::Tombstoned));
    assert!(store.is_tombstoned(digest));
    assert_eq!(store.tombstone_record(digest), Some(&record));

    // Payload bytes and quota are released:
    assert_eq!(store.total_bytes(), b"deletion-witness-001".len() as u64);

    // read_verified returns typed Tombstoned error:
    let read_result = store.read_verified(digest);
    assert!(matches!(read_result, Err(ObjectError::Tombstoned(d)) if d == digest));

    Ok(())
}

/// Positive: publish_manifest fails when referencing a tombstoned child,
/// and tombstoning a child unpublishes any published parent manifest.
#[test]
fn publish_and_closure_verification_fail_naming_tombstoned_child() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 8192));
    let child_a = store.put_verified(b"child-a")?;
    let child_b = store.put_verified(b"child-b")?;
    let witness = store.put_verified(b"witness-auth")?;

    // Tombstone child_a before publishing:
    let record_a = sample_tombstone("obj-child-a", 1, child_a, Some(witness))?;
    store.tombstone(child_a, record_a)?;

    // Attempting to publish manifest referencing child_a must fail naming child_a:
    let manifest = ObjectManifest::new("incident", [child_a, child_b], None)?;
    let pub_result = store.publish_manifest(manifest);
    assert!(matches!(pub_result, Err(ObjectError::Tombstoned(d)) if d == child_a));

    // Now publish a valid manifest referencing only child_b:
    let valid_manifest = ObjectManifest::new("incident-valid", [child_b], None)?;
    let receipt = store.publish_manifest(valid_manifest)?;
    assert_eq!(store.verify_closure(receipt.root)?, 2);
    assert_eq!(store.published_manifest_count(), 1);

    // Later, child_b is tombstoned:
    let record_b = sample_tombstone("obj-child-b", 1, child_b, Some(witness))?;
    store.tombstone(child_b, record_b)?;

    // Child is tombstoned; parent manifest is unpublished:
    assert_eq!(store.published_manifest_count(), 0);
    assert!(matches!(
        store.published_manifest(receipt.root),
        Err(ObjectError::ManifestNotPublished(r)) if r == receipt.root
    ));
    // verify_closure must still fail closed after child is tombstoned:
    let verify_result = store.verify_closure(receipt.root);
    assert!(matches!(
        verify_result,
        Err(ObjectError::ManifestNotPublished(r)) if r == receipt.root
    ));
    assert!(store.closure_contains_tombstone(receipt.root));
    assert_eq!(
        store.published_manifests_with_tombstoned_closure(),
        vec![receipt.root]
    );

    Ok(())
}

/// Positive: published manifests whose closure contains a tombstoned child
/// are reported by published_manifests_with_tombstoned_closure.
#[test]
fn closure_query_reports_manifests_with_tombstoned_descendants() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(32, 16384));
    let leaf_1 = store.put_verified(b"leaf-1")?;
    let leaf_2 = store.put_verified(b"leaf-2")?;
    let witness = store.put_verified(b"witness-auth")?;

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
    let record = sample_tombstone("obj-leaf-1", 1, leaf_1, Some(witness))?;
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

    // Only clean_root remains visible:
    assert_eq!(store.published_manifest_count(), 1);
    assert!(store.published_manifest(clean_root).is_ok());
    assert!(store.published_manifest(sub_root).is_err());
    assert!(store.published_manifest(parent_root).is_err());

    Ok(())
}

/// Planted Negative: Tombstoning an unknown or staged object is refused.
#[test]
fn tombstoning_unknown_or_staged_object_is_refused() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 4096));
    let witness = store.put_verified(b"witness-auth")?;

    // Case 1: Unknown object
    let unknown_digest = ContentDigest::sha256(b"not-present");
    let record_unknown = sample_tombstone("obj-unknown", 1, unknown_digest, Some(witness))?;
    let unknown_res = store.tombstone(unknown_digest, record_unknown);
    assert!(matches!(unknown_res, Err(ObjectError::Missing(d)) if d == unknown_digest));

    // Case 2: Staged object (not verified)
    let staged_digest = store.stage(b"staged-only")?;
    assert_eq!(store.state(staged_digest), Some(ObjectState::Staged));
    let record_staged = sample_tombstone("obj-staged", 1, staged_digest, Some(witness))?;
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
    let witness = store.put_verified(b"witness-auth")?;
    let wrong_digest = ContentDigest::sha256(b"wrong-content");

    let mismatched_record = sample_tombstone("obj-mismatch", 1, wrong_digest, Some(witness))?;
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
    let witness = store.put_verified(b"witness-auth")?;

    let record = sample_tombstone("obj-resurrect-target", 1, digest, Some(witness))?;
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
    assert_eq!(store.total_bytes(), b"witness-auth".len() as u64);

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
    let witness = store.put_verified(b"witness-auth")?;

    let record = sample_tombstone("obj-idempotent", 1, digest, Some(witness))?;
    store.tombstone(digest, record.clone())?;

    let bytes_after_first = store.total_bytes();
    assert_eq!(bytes_after_first, b"witness-auth".len() as u64);

    // Second call with identical record succeeds idempotently:
    store.tombstone(digest, record.clone())?;
    assert_eq!(store.total_bytes(), b"witness-auth".len() as u64);
    assert_eq!(store.object_count(), 2);
    assert_eq!(store.state(digest), Some(ObjectState::Tombstoned));

    // Third call with conflicting record (different generation and reason):
    let conflict_witness = store.put_verified(b"conflict-witness")?;
    let conflicting_record = TombstoneRecord::new(
        ObjectId::parse("obj-idempotent")?,
        Generation::parse_positive(3)?,
        Generation::parse_positive(2)?,
        TombstoneReason::Expired,
        Some(conflict_witness),
        digest,
    )?;
    let conflict_res = store.tombstone(digest, conflicting_record);
    assert!(matches!(conflict_res, Err(ObjectError::TombstoneConflict(d)) if d == digest));

    Ok(())
}

/// Positive: Tombstoning a published manifest root removes it from visible_manifests
/// and unpublishes it from active manifest queries.
#[test]
fn tombstoning_manifest_root_unpublishes_manifest_and_drops_from_visible_manifests()
-> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 4096));
    let leaf = store.put_verified(b"leaf-payload")?;
    let manifest = ObjectManifest::new("incident", [leaf], None)?;
    let root = store.publish_manifest(manifest)?.root;
    let witness = store.put_verified(b"witness-auth")?;

    assert_eq!(store.published_manifest_count(), 1);

    let record = sample_tombstone("obj-manifest-root", 1, root, Some(witness))?;
    store.tombstone(root, record)?;

    // published_manifest_count decrements to 0:
    assert_eq!(store.published_manifest_count(), 0);

    // Revoked root is not reported as an active published manifest with tombstoned closure:
    assert!(
        store
            .published_manifests_with_tombstoned_closure()
            .is_empty()
    );

    // published_manifest returns ManifestNotPublished:
    assert!(matches!(
        store.published_manifest(root),
        Err(ObjectError::ManifestNotPublished(r)) if r == root
    ));

    Ok(())
}

/// Planted Negative: A tombstone record with an unverified or missing witness digest is refused.
#[test]
fn tombstone_with_unverified_witness_digest_is_refused() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 4096));
    let digest = store.put_verified(b"data")?;

    // Case 1: Missing witness
    let unverified_witness = ContentDigest::sha256(b"missing-witness");
    let record_missing = TombstoneRecord::new(
        ObjectId::parse("obj-evidence-missing")?,
        Generation::parse_positive(2)?,
        Generation::parse_positive(1)?,
        TombstoneReason::Deleted,
        Some(unverified_witness),
        digest,
    )?;

    let res_missing = store.tombstone(digest, record_missing);
    assert!(matches!(
        res_missing,
        Err(ObjectError::Missing(w)) if w == unverified_witness
    ));

    // Case 2: Staged (not verified) witness
    let staged_witness = store.stage(b"staged-witness-proof")?;
    let record_staged = TombstoneRecord::new(
        ObjectId::parse("obj-evidence-staged")?,
        Generation::parse_positive(2)?,
        Generation::parse_positive(1)?,
        TombstoneReason::Deleted,
        Some(staged_witness),
        digest,
    )?;

    let res_staged = store.tombstone(digest, record_staged);
    assert!(matches!(
        res_staged,
        Err(ObjectError::NotVerified(w)) if w == staged_witness
    ));

    // Target object remains Verified:
    assert_eq!(store.state(digest), Some(ObjectState::Verified));

    // Case 3: Verified witness succeeds
    let verified_witness = store.put_verified(b"verified-witness-proof")?;
    let record_valid = TombstoneRecord::new(
        ObjectId::parse("obj-evidence-valid")?,
        Generation::parse_positive(2)?,
        Generation::parse_positive(1)?,
        TombstoneReason::Deleted,
        Some(verified_witness),
        digest,
    )?;

    store.tombstone(digest, record_valid.clone())?;
    assert_eq!(store.state(digest), Some(ObjectState::Tombstoned));
    assert_eq!(store.tombstone_record(digest), Some(&record_valid));

    Ok(())
}

/// Planted Negative: A tombstone with no witness is rejected with MissingDeletionAuthority,
/// preventing unauthorized deletion (PinkCoast Finding 1).
#[test]
fn tombstone_without_witness_rejected_without_deletion_authority() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 4096));
    let digest = store.put_verified(b"critical-evidence")?;
    assert_eq!(store.total_bytes(), 17);

    let record = TombstoneRecord::new(
        ObjectId::parse("obj-evidence-unwitnessed")?,
        Generation::parse_positive(2)?,
        Generation::parse_positive(1)?,
        TombstoneReason::Deleted,
        None,
        digest,
    )?;

    let res = store.tombstone(digest, record);
    assert!(matches!(res, Err(ObjectError::MissingDeletionAuthority(d)) if d == digest));
    assert_eq!(store.state(digest), Some(ObjectState::Verified));
    assert_eq!(store.total_bytes(), 17);
    assert_eq!(store.read_verified(digest)?, b"critical-evidence");
    Ok(())
}

/// Positive: When a leaf child is tombstoned, published parent manifests are unpublished,
/// preventing visible manifests from serving broken closures (PinkCoast Finding 2).
#[test]
fn published_parent_manifest_unpublished_when_child_tombstoned() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 4096));
    let leaf = store.put_verified(b"leaf-payload")?;
    let manifest = ObjectManifest::new("incident", [leaf], None)?;
    let root = store.publish_manifest(manifest)?.root;

    assert_eq!(store.published_manifest_count(), 1);
    assert!(store.published_manifest(root).is_ok());

    let witness = store.put_verified(b"deletion-witness")?;
    let record = TombstoneRecord::new(
        ObjectId::parse("obj-leaf")?,
        Generation::parse_positive(2)?,
        Generation::parse_positive(1)?,
        TombstoneReason::Deleted,
        Some(witness),
        leaf,
    )?;
    store.tombstone(leaf, record)?;

    // Manifest is unpublished from visible manifests:
    assert_eq!(store.published_manifest_count(), 0);
    assert!(matches!(
        store.published_manifest(root),
        Err(ObjectError::ManifestNotPublished(r)) if r == root
    ));
    assert!(matches!(
        store.verify_closure(root),
        Err(ObjectError::ManifestNotPublished(r)) if r == root
    ));
    assert!(store.closure_contains_tombstone(root));
    assert_eq!(
        store.published_manifests_with_tombstoned_closure(),
        vec![root]
    );
    Ok(())
}

/// Positive: Idempotent tombstone re-application succeeds even if the original deletion
/// witness is subsequently tombstoned during cascading deletion (PinkCoast Finding 3).
#[test]
fn tombstone_idempotence_preserved_when_witness_tombstoned() -> Result<(), Box<dyn Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 4096));
    let data = store.put_verified(b"data")?;
    let witness = store.put_verified(b"witness-proof")?;

    let record = TombstoneRecord::new(
        ObjectId::parse("obj-data")?,
        Generation::parse_positive(2)?,
        Generation::parse_positive(1)?,
        TombstoneReason::Deleted,
        Some(witness),
        data,
    )?;

    store.tombstone(data, record.clone())?;
    assert_eq!(store.state(data), Some(ObjectState::Tombstoned));

    // Later, the witness itself is tombstoned:
    let meta_witness = store.put_verified(b"meta-witness")?;
    let witness_tombstone = TombstoneRecord::new(
        ObjectId::parse("obj-witness")?,
        Generation::parse_positive(2)?,
        Generation::parse_positive(1)?,
        TombstoneReason::Deleted,
        Some(meta_witness),
        witness,
    )?;
    store.tombstone(witness, witness_tombstone)?;

    // Re-applying identical tombstone record to `data` must succeed idempotently:
    assert!(store.tombstone(data, record).is_ok());
    Ok(())
}
