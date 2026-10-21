#![forbid(unsafe_code)]
//! Deletion invalidates graph authority without erasing independently retained payloads.

use super::*;
use fss_core::{Generation, ObjectId, TombstoneReason};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    store: InMemoryObjectStore,
    survivor: ContentDigest,
    deleted: ContentDigest,
    inner: ObjectManifest,
    outer: ObjectManifest,
}

impl Fixture {
    fn live() -> Result<Self, Box<dyn std::error::Error>> {
        let mut store = InMemoryObjectStore::new(ObjectLimits::new(64, 1_048_576));
        let survivor = store.put_verified(b"independently retained source")?;
        let deleted = store.put_verified(b"required provenance selected for deletion")?;
        let inner = ObjectManifest::new("inner", [survivor], Some(deleted))?;
        store.publish_manifest(inner.clone())?;
        let outer = ObjectManifest::new("outer", [inner.root()], None)?;
        store.publish_manifest(outer.clone())?;
        Ok(Self { store, survivor, deleted, inner, outer })
    }

    fn delete_metadata(&mut self) -> TestResult {
        let witness = self.store.put_verified(b"owner-authorized deletion witness")?;
        self.store.tombstone(self.deleted, TombstoneRecord::new(
            ObjectId::parse("object:deleted-provenance")?, Generation(2), Generation(1),
            TombstoneReason::Deleted, Some(witness), self.deleted,
        )?)?;
        assert_eq!(self.store.published_manifest_count(), 0);
        assert_eq!(self.store.state(self.inner.root()), Some(ObjectState::Verified));
        assert_eq!(self.store.state(self.outer.root()), Some(ObjectState::Verified));
        Ok(())
    }
}

fn assert_unchanged(before: &InMemoryObjectStore, after: &InMemoryObjectStore) {
    assert_eq!(before.objects, after.objects);
    assert_eq!(before.visible_manifests, after.visible_manifests);
    assert_eq!(before.invalidated_manifests, after.invalidated_manifests);
    assert_eq!(before.total_bytes, after.total_bytes);
    assert_eq!(before.limits, after.limits);
}

#[test]
fn deleted_graphs_cannot_be_laundered_through_a_new_parent_in_any_staging_state() -> TestResult {
    for outer in [false, true] {
        for state in [None, Some(ObjectState::Staged), Some(ObjectState::Verified)] {
            let mut f = Fixture::live()?;
            f.delete_metadata()?;
            let invalid = if outer { f.outer.root() } else { f.inner.root() };
            let wrapper = ObjectManifest::new("replacement", [f.survivor], Some(invalid))?;
            if let Some(state) = state {
                assert_eq!(f.store.stage(&wrapper.try_canonical_bytes()?)?, wrapper.root());
                if state == ObjectState::Verified { f.store.verify(wrapper.root())?; }
            }
            let before = f.store.clone();
            assert!(matches!(f.store.publish_manifest(wrapper.clone()),
                Err(ObjectError::NotVerified(root)) if root == invalid));
            assert_eq!(f.store.state(wrapper.root()), state);
            assert_unchanged(&before, &f.store);
            // Retained historical metadata is not falsely described as corrupt or deleted.
            assert!(f.store.read_verified(invalid).is_ok());
            assert!(f.store.closure_contains_tombstone(invalid));
        }
    }
    Ok(())
}

#[test]
fn invalidated_ancestor_republication_cannot_restore_visibility_or_clear_deletion() -> TestResult {
    let mut f = Fixture::live()?;
    f.delete_metadata()?;
    let before = f.store.clone();
    for _ in 0..2 {
        assert!(matches!(f.store.publish_manifest(f.outer.clone()),
            Err(ObjectError::NotVerified(root)) if root == f.outer.root()));
        assert!(matches!(f.store.published_manifest(f.outer.root()),
            Err(ObjectError::ManifestNotPublished(root)) if root == f.outer.root()));
        assert!(f.store.is_tombstoned(f.deleted));
        assert_unchanged(&before, &f.store);
    }
    Ok(())
}

#[test]
fn shared_surviving_payload_can_be_published_under_a_genuinely_independent_graph() -> TestResult {
    let mut f = Fixture::live()?;
    f.delete_metadata()?;
    let invalidated = f.store.invalidated_manifests.clone();
    let independent = ObjectManifest::new("independent_source", [f.survivor], None)?;
    let receipt = f.store.publish_manifest(independent.clone())?;
    assert_eq!(receipt.closure_object_count, 2);
    assert_eq!(f.store.verify_closure(independent.root())?, 2);
    assert_eq!(f.store.read_verified(f.survivor)?, b"independently retained source");
    assert!(!f.store.closure_contains_tombstone(independent.root()));
    assert_eq!(f.store.invalidated_manifests, invalidated);
    assert!(f.store.is_tombstoned(f.deleted));
    Ok(())
}

#[test]
fn never_published_manifest_looking_bytes_remain_opaque_without_signature_sniffing() -> TestResult {
    let mut store = InMemoryObjectStore::new(ObjectLimits::default());
    let absent = ContentDigest::sha256(b"never retained");
    let encoded = ObjectManifest::new("unpublished", [absent], None)?;
    let leaf = store.put_verified(&encoded.try_canonical_bytes()?)?;
    assert_eq!(leaf, encoded.root());
    let parent = ObjectManifest::new("opaque_parent", [leaf], None)?;
    assert_eq!(store.publish_manifest(parent.clone())?.closure_object_count, 2);
    assert_eq!(store.verify_closure(parent.root())?, 2);
    assert_eq!(store.state(absent), None);
    assert_eq!(store.published_manifest_count(), 1);
    Ok(())
}

#[test]
fn stale_visible_entries_do_not_override_a_known_deletion_invalidation() -> TestResult {
    let mut f = Fixture::live()?;
    f.delete_metadata()?;
    for manifest in [f.inner.clone(), f.outer.clone()] {
        // Fault injection into the private catalogue models stale publication-cache state.
        f.store.visible_manifests.insert(manifest.root(), manifest.clone());
        let before = f.store.clone();
        assert!(matches!(f.store.published_manifest(manifest.root()),
            Err(ObjectError::NotVerified(root)) if root == manifest.root()));
        assert!(matches!(f.store.verify_closure(manifest.root()),
            Err(ObjectError::NotVerified(root)) if root == manifest.root()));
        assert_unchanged(&before, &f.store);
    }
    Ok(())
}

#[test]
fn full_closure_verification_refuses_an_invalidated_opaque_child_in_stale_cache() -> TestResult {
    let mut f = Fixture::live()?;
    f.delete_metadata()?;
    let wrapper = ObjectManifest::new("stale_wrapper", [f.survivor], Some(f.inner.root()))?;
    f.store.put_verified(&wrapper.try_canonical_bytes()?)?;
    // Such a new publication is rejected by the public API; also defend the read boundary.
    f.store.visible_manifests.insert(wrapper.root(), wrapper.clone());
    let before = f.store.clone();
    assert!(matches!(f.store.verify_closure(wrapper.root()),
        Err(ObjectError::NotVerified(root)) if root == f.inner.root()));
    assert_unchanged(&before, &f.store);
    Ok(())
}

#[test]
fn closure_verification_rejects_substituted_cached_descendant_edges() -> TestResult {
    let mut f = Fixture::live()?;
    let different = ObjectManifest::new("substituted", [f.survivor], None)?;
    f.store.visible_manifests.insert(f.inner.root(), different);
    let before = f.store.clone();
    // The original object bytes are intact; the cached typed graph has a different identity.
    assert!(f.store.read_verified(f.inner.root()).is_ok());
    assert!(matches!(f.store.verify_closure(f.outer.root()),
        Err(ObjectError::Corrupt(root)) if root == f.inner.root()));
    assert!(matches!(f.store.publish_manifest(f.outer.clone()),
        Err(ObjectError::Corrupt(root)) if root == f.inner.root()));
    assert_unchanged(&before, &f.store);
    Ok(())
}
