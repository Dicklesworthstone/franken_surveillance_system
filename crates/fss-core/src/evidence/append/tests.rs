use std::error::Error;

use super::*;
use crate::{CaptureInterval, ContentDigest, EvidenceDelta, ObjectId, Plane, TimestampNs};

type TestResult = Result<(), Box<dyn Error>>;

fn next_batch(ledger: &ReferenceLedger, tag: &str) -> Result<EvidenceDeltaBatch, ContractError> {
    ledger.prepare_batch(
        BatchId::parse(format!("batch:{tag}"))?,
        vec![EvidenceDelta {
            delta_id: format!("delta:{tag}"),
            family: "sensor_capsule".to_owned(),
            object_id: ObjectId::parse(format!("object:{tag}"))?,
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
            plane: Plane::Authority,
            payload_digest: ContentDigest::sha256(tag.as_bytes()),
            witness_digest: None,
            operation_id: None,
        }],
        [],
    )
}

#[test]
fn staged_append_keeps_history_private_until_commit_and_matches_replay() -> TestResult {
    let mut ledger = ReferenceLedger::new("site:staged");
    for index in 0..8 {
        let batch = next_batch(&ledger, &index.to_string())?;
        ledger.append(batch)?;
    }
    let before = ledger.current().clone();
    let history = ledger.batches().to_vec();
    let successor = next_batch(&ledger, "next")?;
    let guard = ledger.stage_append(successor.clone())?;
    assert_eq!(guard.basis(), &before);
    assert_eq!(guard.batch(), &successor);
    let prepared = guard.suspend();
    assert_eq!(prepared.batch(), &successor);
    assert_eq!(ledger.current(), &before);
    assert_eq!(ledger.batches(), history.as_slice());

    let committed = ledger.resume_append(prepared)?.commit();
    assert_eq!(committed.anchor, successor.new_anchor);
    assert_eq!(ledger.batches().last(), Some(&successor));
    assert_eq!(ledger.snapshot_at(8), Some(&before));
    let replay = ReferenceLedger::replay("site:staged", ledger.batches().iter().cloned())?;
    for sequence in 0..=9 {
        assert_eq!(ledger.snapshot_at(sequence), replay.snapshot_at(sequence));
    }
    Ok(())
}

#[test]
fn abandoned_append_does_not_consume_identity_or_publish_state() -> TestResult {
    let mut ledger = ReferenceLedger::new("site:staged");
    let before = ledger.current().clone();
    let batch = next_batch(&ledger, "abandoned")?;
    drop(ledger.stage_append(batch.clone())?);
    assert_eq!(ledger.current(), &before);
    assert!(ledger.batches().is_empty());
    let suspended = ledger.stage_append(batch.clone())?.suspend();
    drop(suspended);
    assert_eq!(ledger.current(), &before);
    ledger.append(batch.clone())?;
    assert_eq!(ledger.current().anchor, batch.new_anchor);
    assert_eq!(ledger.batches(), [batch]);
    Ok(())
}

#[test]
fn foreign_owner_at_identical_anchor_cannot_install_a_suspended_append() -> TestResult {
    let mut owner = ReferenceLedger::new("site:staged");
    let mut foreign = ReferenceLedger::new("site:staged");
    assert_eq!(owner.current(), foreign.current());
    let batch = next_batch(&owner, "foreign")?;
    let prepared = owner.stage_append(batch.clone())?.suspend();

    let refusal = foreign
        .resume_append(prepared)
        .err()
        .ok_or("foreign owner accepted another ledger's stage")?;
    assert_eq!(refusal.error(), &ContractError::StaleAnchor);
    let (error, prepared) = refusal.into_parts();
    assert_eq!(error, ContractError::StaleAnchor);
    assert_eq!(prepared.batch(), &batch);
    assert!(foreign.batches().is_empty());
    assert!(owner.batches().is_empty());
    owner.resume_append(prepared)?.commit();
    assert_eq!(owner.current().anchor, batch.new_anchor);
    assert!(foreign.batches().is_empty());
    Ok(())
}

#[test]
fn copied_history_gets_a_distinct_append_owner() -> TestResult {
    let mut owner = ReferenceLedger::new("site:staged");
    let first = next_batch(&owner, "first")?;
    owner.append(first)?;
    let batch = next_batch(&owner, "copied")?;
    let prepared = owner.stage_append(batch.clone())?.suspend();
    let mut copied = owner.clone();
    assert_eq!(copied.current(), owner.current());
    assert_eq!(copied.batches(), owner.batches());

    let refusal = copied
        .resume_append(prepared)
        .err()
        .ok_or("cloned branch accepted the original owner's stage")?;
    let (error, prepared) = refusal.into_parts();
    assert_eq!(error, ContractError::StaleAnchor);
    assert_eq!(prepared.batch(), &batch);
    owner.resume_append(prepared)?.commit();
    assert_eq!(owner.current().anchor.commit_sequence, 2);
    assert_eq!(copied.current().anchor.commit_sequence, 1);
    Ok(())
}

#[test]
fn competing_suspended_append_refuses_an_advanced_basis_without_mutation() -> TestResult {
    let mut ledger = ReferenceLedger::new("site:staged");
    let first = next_batch(&ledger, "first")?;
    let competing = next_batch(&ledger, "competing")?;
    let first_stage = ledger.stage_append(first.clone())?.suspend();
    let competing_stage = ledger.stage_append(competing.clone())?.suspend();
    ledger.resume_append(first_stage)?.commit();
    let before = ledger.current().clone();
    let history = ledger.batches().to_vec();
    let refusal = ledger
        .resume_append(competing_stage)
        .err()
        .ok_or("advanced owner accepted a stale stage")?;
    let (error, prepared) = refusal.into_parts();
    assert_eq!(error, ContractError::StaleAnchor);
    assert_eq!(prepared.batch(), &competing);
    assert_eq!(ledger.current(), &before);
    assert_eq!(ledger.batches(), history.as_slice());
    assert_eq!(ledger.batches(), [first]);
    Ok(())
}

#[test]
fn repeated_suspend_and_resume_preserve_the_unpublished_head() -> TestResult {
    let mut ledger = ReferenceLedger::new("site:staged");
    let before = ledger.current().clone();
    let batch = next_batch(&ledger, "resumed")?;
    let mut prepared = ledger.stage_append(batch.clone())?.suspend();
    for _ in 0..16 {
        let guard = ledger.resume_append(prepared)?;
        assert_eq!(guard.basis(), &before);
        assert_eq!(guard.batch(), &batch);
        prepared = guard.suspend();
        assert_eq!(ledger.current(), &before);
        assert!(ledger.batches().is_empty());
    }
    ledger.resume_append(prepared)?.commit();
    assert_eq!(ledger.current().anchor, batch.new_anchor);
    assert_eq!(ledger.batches(), [batch]);
    Ok(())
}

#[test]
fn staging_preserves_identity_and_validation_refusals_without_publication() -> TestResult {
    let mut ledger = ReferenceLedger::new("site:staged");
    let first = next_batch(&ledger, "first")?;
    ledger.append(first.clone())?;
    let before = ledger.current().clone();
    let mut reused = next_batch(&ledger, "second")?;
    reused.batch_id = first.batch_id.clone();
    reused.batch_digest = reused.computed_digest();
    let mut corrupt = next_batch(&ledger, "third")?;
    corrupt.batch_digest = ContentDigest::sha256(b"not-the-batch");
    for (batch, expected) in [
        (reused, ContractError::IdempotencyConflict),
        (first.clone(), ContractError::StaleAnchor),
        (corrupt, ContractError::DigestMismatch),
    ] {
        assert_eq!(ledger.stage_append(batch).err(), Some(expected));
        assert_eq!(ledger.current(), &before);
        assert_eq!(ledger.batches(), [first.clone()]);
    }
    let valid = next_batch(&ledger, "valid")?;
    ledger.stage_append(valid)?.commit();
    assert_eq!(ledger.current().anchor.commit_sequence, 2);
    Ok(())
}
