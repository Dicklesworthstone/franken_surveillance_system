#![forbid(unsafe_code)]
//! Integration tests demonstrating and proving defects in fss-publication.

use std::error::Error;
use std::fs;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, ObjectId, Plane, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectError, ObjectLimits};
use fss_publication::{AuthorityPublisher, PublicationError};

fn temp_journal(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "fss-pub-defect-{}-{name}.journal",
        std::process::id()
    ))
}

fn sample_delta(
    payload: ContentDigest,
    witness: Option<ContentDigest>,
) -> Result<EvidenceDelta, Box<dyn Error>> {
    Ok(EvidenceDelta {
        delta_id: "delta:test:1".to_owned(),
        family: "sensor_capsule".to_owned(),
        object_id: ObjectId::parse("object:sensor-capsule:1")?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval::new(TimestampNs(100), TimestampNs(120))?,
        plane: Plane::Authority,
        payload_digest: payload,
        witness_digest: witness,
        operation_id: None,
    })
}

/// F1: Delta payload must be verified in the object catalog before prepare_batch or append succeeds.
#[test]
fn delta_payload_missing_from_store_must_block_authority_commit() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("missing-delta-payload");
    let _ = fs::remove_file(&path);
    let store = InMemoryObjectStore::new(ObjectLimits::new(8, 4096));
    let mut ledger = DurableReferenceLedger::open(&path, "site:one", IncompleteTailPolicy::Reject)?;
    let missing_payload = ContentDigest::sha256(b"missing-payload");
    let delta = sample_delta(missing_payload, None)?;

    let mut publisher = AuthorityPublisher::new(&store, &mut ledger);
    // Prepare batch with empty child_roots (omitting missing_payload):
    let prepare_result =
        publisher.prepare_batch(BatchId::parse("batch:publication:1")?, vec![delta], []);
    match prepare_result {
        Ok(batch) => {
            // If prepare_batch failed to reject, append MUST reject:
            let append_result = publisher.append(batch);
            if append_result.is_ok() {
                let _ = fs::remove_file(path);
                return Err(
                    "F1 defect confirmed: append committed batch with missing delta payload".into(),
                );
            }
        }
        Err(PublicationError::Object(ObjectError::Missing(d))) if d == missing_payload => {
            // Expected fixed behavior
        }
        Err(other) => {
            let _ = fs::remove_file(path);
            return Err(format!("unexpected error variant: {other:?}").into());
        }
    }

    let _ = fs::remove_file(path);
    Ok(())
}

/// F1: Delta witness digest must be verified in the object catalog before prepare_batch or append succeeds.
#[test]
fn delta_witness_missing_from_store_must_block_authority_commit() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("missing-delta-witness");
    let _ = fs::remove_file(&path);
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(8, 4096));
    let payload = store.put_verified(b"payload-bytes")?;
    let mut ledger = DurableReferenceLedger::open(&path, "site:one", IncompleteTailPolicy::Reject)?;
    let missing_witness = ContentDigest::sha256(b"missing-witness");
    let delta = sample_delta(payload, Some(missing_witness))?;

    let mut publisher = AuthorityPublisher::new(&store, &mut ledger);
    let prepare_result = publisher.prepare_batch(
        BatchId::parse("batch:publication:1")?,
        vec![delta],
        [payload],
    );
    match prepare_result {
        Ok(batch) => {
            let append_result = publisher.append(batch);
            if append_result.is_ok() {
                let _ = fs::remove_file(path);
                return Err(
                    "F1 defect confirmed: append committed batch with missing witness object"
                        .into(),
                );
            }
        }
        Err(PublicationError::Object(ObjectError::Missing(d))) if d == missing_witness => {
            // Expected fixed behavior
        }
        Err(other) => {
            let _ = fs::remove_file(path);
            return Err(format!("unexpected error variant: {other:?}").into());
        }
    }

    let _ = fs::remove_file(path);
    Ok(())
}

/// F6: Retrying append of an identical already-committed batch must be idempotent and succeed.
#[test]
fn retry_append_of_already_committed_batch_must_be_idempotent() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("idempotent-retry");
    let _ = fs::remove_file(&path);
    let mut store = InMemoryObjectStore::new(ObjectLimits::new(8, 4096));
    let child = store.put_verified(b"child-data")?;
    let mut ledger = DurableReferenceLedger::open(&path, "site:one", IncompleteTailPolicy::Reject)?;

    let mut publisher = AuthorityPublisher::new(&store, &mut ledger);
    let batch = publisher.prepare_batch(
        BatchId::parse("batch:publication:1")?,
        vec![sample_delta(child, None)?],
        [child],
    )?;

    let first_anchor = publisher.append(batch.clone())?;

    let retry_result = publisher.append(batch);
    match retry_result {
        Ok(anchor) => {
            if anchor != first_anchor {
                let _ = fs::remove_file(path);
                return Err("retry returned anchor mismatch".into());
            }
        }
        Err(error) => {
            let _ = fs::remove_file(path);
            return Err(format!("F6 defect confirmed: append retry failed with: {error:?}").into());
        }
    }

    let _ = fs::remove_file(path);
    Ok(())
}

/// PinkCoast finding 2: Conflicting batch carrying an already-committed BatchId must be
/// rejected with typed PublicationError::DuplicateBatchId.
#[test]
fn conflicting_batch_with_same_batch_id_is_rejected() -> Result<(), Box<dyn Error>> {
    let journal_path = temp_journal("duplicate-batch-id");
    let _ = fs::remove_file(&journal_path);

    let mut store = InMemoryObjectStore::new(ObjectLimits::new(16, 8192));
    let payload_1 = store.put_verified(b"payload-1")?;
    let payload_2 = store.put_verified(b"payload-2")?;
    let mut ledger =
        DurableReferenceLedger::open(&journal_path, "site:one", IncompleteTailPolicy::Reject)?;

    let mut publisher = AuthorityPublisher::new(&store, &mut ledger);
    let batch_id = BatchId::parse("batch:test:duplicate-id")?;

    let delta_1 = EvidenceDelta {
        delta_id: "delta:1".to_owned(),
        family: "sensor_capsule".to_owned(),
        object_id: ObjectId::parse("object:sensor-capsule:1")?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval::new(TimestampNs(100), TimestampNs(120))?,
        plane: Plane::Authority,
        payload_digest: payload_1,
        witness_digest: None,
        operation_id: None,
    };

    let batch_1 = publisher.prepare_batch(batch_id.clone(), vec![delta_1], [payload_1])?;
    let _anchor_1 = publisher.append(batch_1)?;

    // Construct batch_2 with the SAME batch_id but DIFFERENT payload:
    let delta_2 = EvidenceDelta {
        delta_id: "delta:2".to_owned(),
        family: "sensor_capsule".to_owned(),
        object_id: ObjectId::parse("object:sensor-capsule:2")?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval::new(TimestampNs(130), TimestampNs(150))?,
        plane: Plane::Authority,
        payload_digest: payload_2,
        witness_digest: None,
        operation_id: None,
    };

    let batch_2 = publisher.prepare_batch(batch_id.clone(), vec![delta_2], [payload_2])?;

    // publisher.append(batch_2) MUST return Err(PublicationError::DuplicateBatchId):
    let append_2_result = publisher.append(batch_2);
    let _ = fs::remove_file(&journal_path);
    match append_2_result {
        Err(PublicationError::DuplicateBatchId(id)) if id == batch_id => Ok(()),
        other => Err(format!(
            "expected PublicationError::DuplicateBatchId({batch_id}), got: {other:?}"
        )
        .into()),
    }
}
