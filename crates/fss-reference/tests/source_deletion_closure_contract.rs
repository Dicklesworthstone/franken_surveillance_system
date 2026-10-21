#![forbid(unsafe_code)]
//! Public source disclosure keeps payload custody distinct from invalidated graph authority.

use fss_core::{
    CanonicalEncode, ContentDigest, Generation, ObjectId, TombstoneReason, TombstoneRecord,
};
use fss_object::{InMemoryObjectStore, ObjectError, ObjectLimits, ObjectManifest, ObjectState};
use fss_reference::{PublishedSourceReader, SourceHydrationError};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn source_disclosure_cannot_reintroduce_a_deleted_graph_through_a_new_parent() -> TestResult {
    let mut store = InMemoryObjectStore::new(ObjectLimits::default());
    let source = store.put_verified(b"source survives independently")?;
    let metadata = store.put_verified(b"required source provenance")?;
    let inner = ObjectManifest::new("source", [source], Some(metadata))?;
    store.publish_manifest(inner.clone())?;
    let original = ObjectManifest::new("event", [inner.root()], None)?;
    store.publish_manifest(original.clone())?;
    assert_eq!(
        store.read_published_source(original.root(), source, 1024)?,
        b"source survives independently"
    );

    let witness = store.put_verified(b"explicit owner deletion authority")?;
    store.tombstone(metadata, TombstoneRecord::new(
        ObjectId::parse("object:source-provenance")?, Generation(2), Generation(1),
        TombstoneReason::Deleted, Some(witness), metadata,
    )?)?;
    let count = store.object_count();
    let bytes = store.total_bytes();
    let replacement = ObjectManifest::new("replacement", [source], Some(inner.root()))?;
    assert!(matches!(store.publish_manifest(replacement.clone()),
        Err(ObjectError::NotVerified(root)) if root == inner.root()));
    for root in [original.root(), replacement.root()] {
        assert!(matches!(store.read_published_source(root, source, 1024),
            Err(SourceHydrationError::Object(ObjectError::ManifestNotPublished(_)))));
    }
    assert_eq!(store.object_count(), count);
    assert_eq!(store.total_bytes(), bytes);
    assert_eq!(store.published_manifest_count(), 0);
    assert_eq!(store.state(metadata), Some(ObjectState::Tombstoned));
    assert_eq!(store.read_verified(source)?, b"source survives independently");

    // Sharing a surviving payload does not make a genuinely independent publication invalid.
    let independent = ObjectManifest::new("independent", [source], None)?;
    store.publish_manifest(independent.clone())?;
    assert_eq!(store.read_published_source(independent.root(), source, 1024)?,
        b"source survives independently");
    assert!(store.closure_contains_tombstone(inner.root()));
    Ok(())
}

#[test]
fn source_reader_preserves_never_published_opaque_leaf_semantics() -> TestResult {
    let mut store = InMemoryObjectStore::new(ObjectLimits::default());
    let absent = ContentDigest::sha256(b"unretained object");
    let unpublished = ObjectManifest::new("looks_like_a_manifest", [absent], None)?;
    let bytes = unpublished.try_canonical_bytes()?;
    let leaf = store.put_verified(&bytes)?;
    let parent = ObjectManifest::new("published", [leaf], None)?;
    store.publish_manifest(parent.clone())?;
    assert_eq!(store.read_published_source(parent.root(), leaf, bytes.len() as u64)?, bytes);
    assert!(matches!(store.read_published_source(parent.root(), absent, 1024),
        Err(SourceHydrationError::NotReachable)));
    assert_eq!(store.state(absent), None);
    assert_eq!(store.published_manifest_count(), 1);
    Ok(())
}
