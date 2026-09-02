use std::collections::BTreeSet;
use std::error::Error;
use std::fs;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, ObjectId, Plane, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{
    InMemoryObjectStore, ObjectError, ObjectLimits, VerifiedObjectCatalog,
};

use crate::{AuthorityPublisher, PublicationError};

fn temp_journal(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "fss-publication-{}-{name}.journal",
        std::process::id()
    ))
}

fn delta(payload: ContentDigest) -> Result<EvidenceDelta, Box<dyn Error>> {
    Ok(EvidenceDelta {
        delta_id: "delta:publication:1".to_owned(),
        family: "sensor_capsule".to_owned(),
        object_id: ObjectId::parse("object:sensor-capsule:1")?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval::new(TimestampNs(100), TimestampNs(120))?,
        plane: Plane::Authority,
        payload_digest: payload,
        witness_digest: None,
        operation_id: None,
    })
}

#[test]
fn missing_child_blocks_prepare_without_advancing_authority() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("missing-child");
    let _ = fs::remove_file(&path);
    let store = InMemoryObjectStore::new(ObjectLimits::new(8, 4096));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:one", IncompleteTailPolicy::Reject)?;
    let missing = ContentDigest::sha256(b"missing");
    {
        let publisher = AuthorityPublisher::new(&store, &mut ledger);
        assert!(matches!(
            publisher.prepare_batch(
                BatchId::parse("batch:publication:1")?,
                vec![delta(missing)?],
                [missing],
            ),
            Err(PublicationError::Object(ObjectError::Missing(found))) if found == missing
        ));
        assert_eq!(publisher.current_anchor().commit_sequence, 0);
    }
    assert_eq!(ledger.batches().len(), 0);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn staged_child_blocks_prepare_until_verified() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("staged-child");
    let _ = fs::remove_file(&path);
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(8, 4096));
    let child = store.stage(b"source-bytes")?;
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:one", IncompleteTailPolicy::Reject)?;
    {
        let publisher = AuthorityPublisher::new(&store, &mut ledger);
        assert!(matches!(
            publisher.prepare_batch(
                BatchId::parse("batch:publication:1")?,
                vec![delta(child)?],
                [child],
            ),
            Err(PublicationError::Object(ObjectError::NotVerified(found))) if found == child
        ));
    }
    store.verify(child)?;
    {
        let publisher = AuthorityPublisher::new(&store, &mut ledger);
        let batch = publisher.prepare_batch(
            BatchId::parse("batch:publication:1")?,
            vec![delta(child)?],
            [child],
        )?;
        assert_eq!(batch.children, vec![child]);
    }
    let _ = fs::remove_file(path);
    Ok(())
}

#[derive(Default)]
struct SwitchingCatalog {
    verified: BTreeSet<ContentDigest>,
    corrupt: BTreeSet<ContentDigest>,
}

impl VerifiedObjectCatalog for SwitchingCatalog {
    fn require_verified(&self, digest: ContentDigest) -> Result<(), ObjectError> {
        if self.corrupt.contains(&digest) {
            return Err(ObjectError::Corrupt(digest));
        }
        if self.verified.contains(&digest) {
            Ok(())
        } else {
            Err(ObjectError::Missing(digest))
        }
    }
}

#[test]
fn append_revalidates_children_after_preparation() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("revalidate");
    let _ = fs::remove_file(&path);
    let child = ContentDigest::sha256(b"child");
    let mut catalog = SwitchingCatalog::default();
    catalog.verified.insert(child);
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:one", IncompleteTailPolicy::Reject)?;

    let batch = {
        let publisher = AuthorityPublisher::new(&catalog, &mut ledger);
        publisher.prepare_batch(
            BatchId::parse("batch:publication:1")?,
            vec![delta(child)?],
            [child],
        )?
    };
    catalog.corrupt.insert(child);

    {
        let mut publisher = AuthorityPublisher::new(&catalog, &mut ledger);
        assert!(matches!(
            publisher.append(batch),
            Err(PublicationError::Object(ObjectError::Corrupt(found))) if found == child
        ));
        assert_eq!(publisher.current_anchor().commit_sequence, 0);
    }
    assert_eq!(ledger.batches().len(), 0);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn verified_children_publish_and_restart_with_exact_roots() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("restart");
    let _ = fs::remove_file(&path);
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 8192));
    let first = store.put_verified(b"source-one")?;
    let second = store.put_verified(b"source-two")?;

    let expected_anchor;
    {
        let mut ledger =
            DurableReferenceLedger::open(&path, "site:one", IncompleteTailPolicy::Reject)?;
        {
            let mut publisher = AuthorityPublisher::new(&store, &mut ledger);
            let batch = publisher.prepare_batch(
                BatchId::parse("batch:publication:1")?,
                vec![delta(first)?],
                [second, first, first],
            )?;
            assert_eq!(batch.children.len(), 2);
            expected_anchor = publisher.append(batch)?;
            assert_eq!(expected_anchor.commit_sequence, 1);
        }
        assert_eq!(ledger.batches()[0].children, {
            let mut children = vec![first, second];
            children.sort_unstable();
            children
        });
    }

    let reopened =
        DurableReferenceLedger::open(&path, "site:one", IncompleteTailPolicy::Reject)?;
    assert_eq!(reopened.current().anchor, expected_anchor);
    assert_eq!(reopened.batches().len(), 1);
    assert_eq!(reopened.batches()[0].children.len(), 2);

    let _ = fs::remove_file(path);
    Ok(())
}
