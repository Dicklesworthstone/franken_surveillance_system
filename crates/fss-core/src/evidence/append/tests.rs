use std::error::Error;

use super::*;
use crate::{
    CaptureInterval, ContentDigest, EvidenceDelta, LedgerSnapshotRetention, ObjectId, Plane,
    TimestampNs,
};

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

#[test]
fn current_snapshot_mode_preserves_history_bytes_without_retaining_old_object_maps() -> TestResult {
    const COMMITS: usize = 128;
    let mut full = ReferenceLedger::new("site:snapshot-retention");
    let mut current = ReferenceLedger::new_with_snapshot_retention(
        "site:snapshot-retention",
        LedgerSnapshotRetention::CurrentOnly,
    );
    assert_eq!(full.snapshot_retention(), LedgerSnapshotRetention::FullHistory);
    assert_eq!(current.retained_snapshot_count(), 1);
    assert_eq!(current.snapshot_at(0), Some(full.current()));
    for index in 0..COMMITS {
        let batch = next_batch(&full, &index.to_string())?;
        full.append(batch.clone())?;
        current.append(batch)?;
        assert_eq!(current.current(), full.current());
        assert_eq!(current.batches(), full.batches());
        assert_eq!(current.retained_snapshot_count(), 1);
        assert_eq!(full.retained_snapshot_count(), index + 2);
        let sequence = u64::try_from(index + 1)?;
        assert_eq!(current.snapshot_at(sequence), Some(full.current()));
        assert!(current.snapshot_at(sequence - 1).is_none());
    }
    // Count real resident map entries, independently of the public count accessor. The new
    // mode retains the current 128 objects instead of all 8,256 historical copies.
    assert_eq!(current.snapshots.len(), 1);
    assert_eq!(current.snapshots[0].objects.len(), COMMITS);
    assert_eq!(
        full.snapshots.iter().map(|snapshot| snapshot.objects.len()).sum::<usize>(),
        COMMITS * (COMMITS + 1) / 2,
    );
    assert_eq!(current.committed_batches, full.committed_batches);

    let replayed = ReferenceLedger::replay_with_snapshot_retention(
        "site:snapshot-retention",
        LedgerSnapshotRetention::CurrentOnly,
        full.batches().iter().cloned(),
    )?;
    assert_eq!(replayed.current(), full.current());
    assert_eq!(replayed.batches(), full.batches());
    assert_eq!(replayed.retained_snapshot_count(), 1);
    let historical = ReferenceLedger::replay("site:snapshot-retention", full.batches().iter().cloned())?;
    for sequence in 0..=u64::try_from(COMMITS)? {
        assert_eq!(historical.snapshot_at(sequence), full.snapshot_at(sequence));
        assert!(historical.snapshot_at(sequence).is_some());
    }
    Ok(())
}

#[test]
fn current_snapshot_stages_preserve_owner_and_visible_state_through_suspension() -> TestResult {
    let mut owner = ReferenceLedger::new_with_snapshot_retention(
        "site:current-stage",
        LedgerSnapshotRetention::CurrentOnly,
    );
    for index in 0..16 {
        let batch = next_batch(&owner, &index.to_string())?;
        owner.append(batch)?;
    }
    let before = owner.current().clone();
    let history = owner.batches().to_vec();
    let abandoned = next_batch(&owner, "abandoned")?;
    drop(owner.stage_append(abandoned)?);
    assert_eq!(owner.current(), &before);
    assert_eq!(owner.batches(), history.as_slice());
    assert_eq!(owner.retained_snapshot_count(), 1);

    let chosen = next_batch(&owner, "chosen")?;
    let competitor = next_batch(&owner, "competitor")?;
    let mut prepared = owner.stage_append(chosen.clone())?.suspend();
    let competing = owner.stage_append(competitor.clone())?.suspend();
    let mut cloned = owner.clone();
    assert_eq!(cloned.snapshot_retention(), LedgerSnapshotRetention::CurrentOnly);
    assert_eq!(cloned.retained_snapshot_count(), 1);
    assert_eq!(cloned.committed_batches, owner.committed_batches);
    let mut full_owner = ReferenceLedger::replay("site:current-stage", history.iter().cloned())?;
    for foreign in [&mut cloned, &mut full_owner] {
        assert_eq!(foreign.current(), &before);
        let refusal = foreign.resume_append(prepared).err().ok_or("foreign stage accepted")?;
        let (error, returned) = refusal.into_parts();
        assert_eq!(error, ContractError::StaleAnchor);
        assert_eq!(returned.batch(), &chosen);
        assert_eq!(foreign.current(), &before);
        assert_eq!(foreign.batches(), history.as_slice());
        prepared = returned;
    }
    for _ in 0..16 {
        let guard = owner.resume_append(prepared)?;
        assert_eq!(guard.basis(), &before);
        prepared = guard.suspend();
        assert_eq!(owner.current(), &before);
        assert_eq!(owner.batches(), history.as_slice());
        assert_eq!(owner.retained_snapshot_count(), 1);
    }
    owner.resume_append(prepared)?.commit();
    assert_eq!(owner.current().anchor, chosen.new_anchor);
    assert_eq!(owner.retained_snapshot_count(), 1);
    assert!(owner.snapshot_at(before.anchor.commit_sequence).is_none());
    assert_eq!(cloned.current(), &before);
    assert_eq!(full_owner.current(), &before);

    let committed = owner.current().clone();
    let refusal = owner.resume_append(competing).err().ok_or("stale stage accepted")?;
    let (error, returned) = refusal.into_parts();
    assert_eq!(error, ContractError::StaleAnchor);
    assert_eq!(returned.batch(), &competitor);
    assert_eq!(owner.current(), &committed);
    assert_eq!(owner.retained_snapshot_count(), 1);
    assert_eq!(owner.batches().last(), Some(&chosen));
    Ok(())
}

#[test]
fn snapshot_modes_keep_all_batch_identities_and_identical_validation_precedence() -> TestResult {
    let mut full = ReferenceLedger::new("site:retained-identities");
    for index in 0..32 {
        let batch = next_batch(&full, &index.to_string())?;
        full.append(batch)?;
    }
    let mut current = ReferenceLedger::replay_with_snapshot_retention(
        "site:retained-identities",
        LedgerSnapshotRetention::CurrentOnly,
        full.batches().iter().cloned(),
    )?;
    let before = full.current().clone();
    let history = full.batches().to_vec();
    let next = next_batch(&full, "next")?;
    let mut reused = next.clone();
    reused.batch_id = history[0].batch_id.clone();
    reused.basis_anchor = history[0].basis_anchor.clone();
    reused.batch_digest = reused.computed_digest();
    let mut bad_successor = next.clone();
    bad_successor.new_anchor.commit_sequence += 1;
    bad_successor.batch_digest = bad_successor.computed_digest();
    let mut bad_digest = next.clone();
    bad_digest.batch_digest = ContentDigest::sha256(b"invalid batch digest");
    let mut bad_state = next.clone();
    bad_state.new_anchor.state_root = ContentDigest::sha256(b"invalid state root");
    bad_state.batch_digest = bad_state.computed_digest();
    for (batch, expected) in [
        (reused, ContractError::IdempotencyConflict),
        (history[0].clone(), ContractError::StaleAnchor),
        (bad_successor, ContractError::InvalidAnchorSuccessor),
        (bad_digest, ContractError::DigestMismatch),
        (bad_state, ContractError::DigestMismatch),
    ] {
        for ledger in [&mut full, &mut current] {
            assert_eq!(ledger.stage_append(batch.clone()).err(), Some(expected.clone()));
            assert_eq!(ledger.current(), &before);
            assert_eq!(ledger.batches(), history.as_slice());
        }
    }
    full.append(next.clone())?;
    current.append(next)?;
    assert_eq!(full.current(), current.current());
    assert_eq!(full.batches(), current.batches());
    assert_eq!(full.committed_batches, current.committed_batches);
    assert_eq!(current.retained_snapshot_count(), 1);
    Ok(())
}
