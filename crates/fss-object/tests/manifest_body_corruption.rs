#![forbid(unsafe_code)]
//! Classification of a corrupt stored copy on restage and republication (fss-gltvf).
//!
//! When the stored bytes behind a content digest no longer rehash to that digest, the stored copy
//! is corrupt. Restaging the canonical bytes, or republishing the manifest whose body it is, must
//! report [`ObjectError::Corrupt`], matching `read_verified`, `verify`, and the on-disk
//! `LocalRootPublisher` (`ReferenceBlocked { ManifestBody, Corrupt }`). A digest collision is a
//! different claim: two distinct byte strings that both hash to the same digest. With SHA-256 and
//! `corrupt_for_test` as the only mutation hook, a genuine collision cannot be constructed through
//! the public API, so these tests pin the clean-restage and clean-republish paths instead.

use std::error::Error;

use fss_core::CanonicalEncode;
use fss_object::{InMemoryObjectStore, ObjectError, ObjectLimits, ObjectManifest, ObjectState};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn corrupt_manifest_body_republication_is_corruption_not_collision() -> TestResult {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 8192));
    let first = store.put_verified(b"clip-segment-0001")?;
    let second = store.put_verified(b"clip-segment-0002")?;
    let manifest = ObjectManifest::new("event_archive", [first, second], None)?;
    let root = manifest.root();
    store.publish_manifest(manifest.clone())?;
    let objects_before = store.object_count();
    let bytes_before = store.total_bytes();

    store.corrupt_for_test(root)?;

    assert_eq!(
        store.publish_manifest(manifest.clone()),
        Err(ObjectError::Corrupt(root))
    );
    // The failed republication neither unpublishes the root nor changes custody accounting.
    assert_eq!(
        store.published_manifest(root),
        Err(ObjectError::Corrupt(root))
    );
    assert_eq!(store.state(root), Some(ObjectState::Verified));
    assert_eq!(store.object_count(), objects_before);
    assert_eq!(store.total_bytes(), bytes_before);
    // A retry is classified identically: the corrupt copy is never overwritten or promoted.
    assert_eq!(
        store.publish_manifest(manifest),
        Err(ObjectError::Corrupt(root))
    );
    assert_eq!(store.read_verified(root), Err(ObjectError::Corrupt(root)));
    Ok(())
}

#[test]
fn restaging_over_a_corrupt_stored_object_is_corruption_not_collision() -> TestResult {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 8192));
    let payload = b"evidence-bytes-to-corrupt";
    let digest = store.put_verified(payload)?;
    let bytes_before = store.total_bytes();

    store.corrupt_for_test(digest)?;

    assert_eq!(store.stage(payload), Err(ObjectError::Corrupt(digest)));
    assert_eq!(
        store.put_verified(payload),
        Err(ObjectError::Corrupt(digest))
    );
    // Restaging never repairs, overwrites, or re-accounts the corrupt stored copy.
    assert_eq!(
        store.read_verified(digest),
        Err(ObjectError::Corrupt(digest))
    );
    assert_eq!(store.state(digest), Some(ObjectState::Verified));
    assert_eq!(store.object_count(), 1);
    assert_eq!(store.total_bytes(), bytes_before);
    Ok(())
}

#[test]
fn restaging_a_staged_object_with_corrupt_stored_bytes_is_corruption() -> TestResult {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 8192));
    let payload = b"staged-but-not-verified";
    let digest = store.stage(payload)?;

    store.corrupt_for_test(digest)?;

    assert_eq!(store.stage(payload), Err(ObjectError::Corrupt(digest)));
    assert_eq!(store.state(digest), Some(ObjectState::Staged));
    assert_eq!(store.verify(digest), Err(ObjectError::Corrupt(digest)));
    Ok(())
}

#[test]
fn clean_restage_and_republication_stay_idempotent() -> TestResult {
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 8192));
    let first = store.put_verified(b"clip-segment-0001")?;
    assert_eq!(store.stage(b"clip-segment-0001")?, first);
    let manifest = ObjectManifest::new("event_clip", [first], None)?;
    let root = manifest.root();
    let receipt = store.publish_manifest(manifest.clone())?;
    let objects_before = store.object_count();
    let bytes_before = store.total_bytes();

    // Restaging the exact canonical body of a visible manifest is not a collision.
    assert_eq!(store.stage(&manifest.canonical_bytes())?, root);
    assert_eq!(store.publish_manifest(manifest)?, receipt);
    assert_eq!(store.object_count(), objects_before);
    assert_eq!(store.total_bytes(), bytes_before);
    Ok(())
}
