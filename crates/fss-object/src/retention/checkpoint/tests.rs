#![forbid(unsafe_code)]

use super::*;
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;
const PRIVATE_SOURCE: &[u8] = b"original private camera bytes are never retention-checkpoint payload";
fn rule(until: i128) -> RetentionRule {
    RetentionRule { retain_until: TimestampNs(until), reason: "rule:reference".to_owned() }
}
fn recovery() -> RetentionRecoveryBudget {
    RetentionRecoveryBudget { max_checkpoint_bytes: 1_000_000, max_custody_bytes: 1_000_000 }
}
fn sweep() -> RetentionBudget {
    RetentionBudget { max_objects: 128, max_deleted_bytes: 1_000_000, max_staging_bytes: 1_000_000 }
}
fn fixture() -> Result<(RetentionStore, ContentDigest, ContentDigest, ContentDigest), Box<dyn Error>> {
    let mut s = RetentionStore::new(ContentDigest::sha256(b"retention-policy"),
        ObjectLimits::new(128, 1_000_000), RetentionLimits::default());
    let witness = s.put_source(b"retention authority witness", rule(10_000))?;
    let source = s.put_source(PRIVATE_SOURCE, rule(1))?;
    let derivative = s.put_derivative(b"private derivative", rule(1), BTreeSet::from([source]))?;
    Ok((s, witness, source, derivative))
}
fn delete(s: &mut RetentionStore, witness: ContentDigest) -> Result<RetentionPlan, RetentionError> {
    let plan = s.prepare_expiry(TimestampNs(10), sweep())?;
    let authorization = RetentionAuthorization { policy_digest: s.policy, plan_digest: plan.digest(),
        witness, permitted_objects: plan.selected().iter().copied().collect(),
        issued_at: TimestampNs(1), expires_at: TimestampNs(100) };
    s.execute_expiry(&plan, &authorization, TimestampNs(10))?;
    Ok(plan)
}
fn restore(s: &RetentionStore, cp: &RetentionCheckpoint) -> Result<RetentionStore, RetentionError> {
    RetentionStore::restore_checkpoint(cp.as_bytes(), cp.digest(), s.policy,
        s.custody(), RetentionLimits::default(), recovery())
}
fn raw_checkpoint(s: &RetentionStore) -> Result<Vec<u8>, RetentionError> {
    let mut e = CanonicalEncoder::new(); e.text(FORMAT); e.bytes(&s.encode_state()?);
    e.u64(s.receipts.len() as u64);
    for receipt in s.receipts.values() { receipt.encode_checkpoint(&mut e); }
    Ok(e.finish_checked()?)
}

#[test]
fn checkpoint_preserves_holds_released_ids_and_canonical_plan() -> TestResult {
    let (mut s, w, source, derivative) = fixture()?;
    s.add_hold(s.state_digest()?, "hold:active", derivative, w)?;
    s.add_hold(s.state_digest()?, "hold:released", source, w)?;
    s.release_hold(s.state_digest()?, "hold:released", w)?;
    let cp = s.checkpoint(1_000_000)?;
    assert!(!cp.as_bytes().windows(PRIVATE_SOURCE.len()).any(|bytes| bytes == PRIVATE_SOURCE));
    let mut restored = restore(&s, &cp)?;
    assert_eq!(restored.state_digest()?, s.state_digest()?);
    assert_eq!(restored.checkpoint(1_000_000)?, cp);
    assert_eq!(restored.prepare_expiry(TimestampNs(10), sweep())?, s.prepare_expiry(TimestampNs(10), sweep())?);
    assert!(restored.prepare_expiry(TimestampNs(10), sweep())?.selected().is_empty());
    assert!(matches!(restored.add_hold(restored.state_digest()?, "hold:released", source, w),
        Err(RetentionError::HoldConflict)));
    restored.release_hold(restored.state_digest()?, "hold:active", w)?;
    assert_eq!(restored.prepare_expiry(TimestampNs(10), sweep())?.selected().len(), 2);
    Ok(())
}

#[test]
fn checkpoint_preserves_deletion_receipts_and_exact_retry_without_payloads() -> TestResult {
    let (mut s, w, source, _) = fixture()?;
    let plan = delete(&mut s, w)?;
    let cp = s.checkpoint(1_000_000)?;
    let mut restored = restore(&s, &cp)?;
    assert!(restored.custody().is_tombstoned(source));
    let authorization = RetentionAuthorization { policy_digest: s.policy, plan_digest: plan.digest(),
        witness: w, permitted_objects: plan.selected().iter().copied().collect(),
        issued_at: TimestampNs(1), expires_at: TimestampNs(100) };
    let receipt = restored.execute_expiry(&plan, &authorization, TimestampNs(11))?;
    assert_eq!(&receipt, s.receipts.get(&plan.digest()).ok_or("missing receipt")?);
    assert_eq!(restored.checkpoint(1_000_000)?, cp);
    assert!(restored.put_source(PRIVATE_SOURCE, rule(1)).is_err());
    assert!(!cp.as_bytes().windows(PRIVATE_SOURCE.len()).any(|bytes| bytes == PRIVATE_SOURCE));
    Ok(())
}

#[test]
fn old_metadata_cannot_be_combined_with_current_deleted_custody() -> TestResult {
    let (mut s, w, _, _) = fixture()?;
    let before = s.checkpoint(1_000_000)?;
    delete(&mut s, w)?;
    assert!(restore(&s, &before).is_err());
    let current = s.checkpoint(1_000_000)?;
    assert!(RetentionStore::restore_checkpoint(current.as_bytes(), before.digest(), s.policy,
        s.custody(), RetentionLimits::default(), recovery()).is_err());
    Ok(())
}

#[test]
fn every_truncation_mutation_and_trailing_byte_fails_the_pinned_root() -> TestResult {
    let (s, _, _, _) = fixture()?;
    let cp = s.checkpoint(1_000_000)?;
    for end in 0..cp.as_bytes().len() {
        assert!(RetentionStore::restore_checkpoint(&cp.as_bytes()[..end], cp.digest(), s.policy,
            s.custody(), RetentionLimits::default(), recovery()).is_err());
    }
    for index in 0..cp.as_bytes().len() {
        let mut bytes = cp.as_bytes().to_vec(); bytes[index] ^= 1;
        assert!(RetentionStore::restore_checkpoint(&bytes, cp.digest(), s.policy,
            s.custody(), RetentionLimits::default(), recovery()).is_err());
    }
    let mut extra = cp.as_bytes().to_vec(); extra.push(0);
    assert!(RetentionStore::restore_checkpoint(&extra, ContentDigest::sha256(&extra), s.policy,
        s.custody(), RetentionLimits::default(), recovery()).is_err());
    Ok(())
}

#[test]
fn accepted_policy_metadata_and_clone_ceilings_are_mandatory() -> TestResult {
    let (s, _, _, _) = fixture()?; let cp = s.checkpoint(1_000_000)?;
    assert!(matches!(RetentionStore::restore_checkpoint(cp.as_bytes(), cp.digest(), ContentDigest::sha256(b"other"),
        s.custody(), RetentionLimits::default(), recovery()), Err(RetentionError::Unauthorized)));
    assert!(s.checkpoint(cp.as_bytes().len() - 1).is_err());
    for budget in [RetentionRecoveryBudget { max_checkpoint_bytes: cp.as_bytes().len()-1, ..recovery() },
        RetentionRecoveryBudget { max_custody_bytes: 0, ..recovery() }]
    {
        assert!(RetentionStore::restore_checkpoint(cp.as_bytes(), cp.digest(), s.policy,
            s.custody(), RetentionLimits::default(), budget).is_err());
    }
    assert!(RetentionStore::restore_checkpoint(cp.as_bytes(), cp.digest(), s.policy, s.custody(),
        RetentionLimits { max_holds: 1, ..RetentionLimits::default() }, recovery()).is_err());
    Ok(())
}

#[test]
fn missing_foreign_corrupt_and_resurrected_objects_are_rejected() -> TestResult {
    let (mut s, w, source, _) = fixture()?;
    let cp = s.checkpoint(1_000_000)?;
    let empty = InMemoryObjectStore::new(s.custody().limits());
    let mut foreign = s.custody().clone(); foreign.put_verified(b"foreign")?;
    let mut corrupt = s.custody().clone(); corrupt.corrupt_for_test(source)?;
    for custody in [&empty, &foreign, &corrupt] {
        assert!(RetentionStore::restore_checkpoint(cp.as_bytes(), cp.digest(), s.policy,
            custody, RetentionLimits::default(), recovery()).is_err());
    }
    let old_custody = s.custody().clone();
    delete(&mut s, w)?; let cp = s.checkpoint(1_000_000)?;
    assert!(RetentionStore::restore_checkpoint(cp.as_bytes(), cp.digest(), s.policy,
        &old_custody, RetentionLimits::default(), recovery()).is_err());
    s.custody().read_verified(w)?;
    Ok(())
}

#[test]
fn changed_tombstone_authority_is_not_equivalent_custody() -> TestResult {
    let (mut s, w, source, derivative) = fixture()?;
    let mut alternate = s.custody().clone();
    delete(&mut s, w)?; let cp = s.checkpoint(1_000_000)?;
    let generation = Generation::parse_positive(1)?;
    for digest in [derivative, source] {
        alternate.tombstone(digest, TombstoneRecord::new(ObjectId::parse("object:other-authority")?,
            generation.next()?, generation, TombstoneReason::Deleted, Some(w), digest)?)?;
    }
    assert!(RetentionStore::restore_checkpoint(cp.as_bytes(), cp.digest(), s.policy,
        &alternate, RetentionLimits::default(), recovery()).is_err());
    Ok(())
}

#[test]
fn resealed_cycles_and_missing_receipts_are_structurally_rejected() -> TestResult {
    let (mut s, _, source, derivative) = fixture()?;
    s.entries.get_mut(&source).ok_or("missing source")?.dependencies.insert(derivative);
    let bytes = raw_checkpoint(&s)?;
    assert!(RetentionStore::restore_checkpoint(&bytes, ContentDigest::sha256(&bytes), s.policy,
        s.custody(), RetentionLimits::default(), recovery()).is_err());
    let (mut s, w, _, _) = fixture()?; delete(&mut s, w)?;
    s.receipts.clear(); s.revision -= 1; s.last_commit_at = None;
    let bytes = raw_checkpoint(&s)?;
    assert!(RetentionStore::restore_checkpoint(&bytes, ContentDigest::sha256(&bytes), s.policy,
        s.custody(), RetentionLimits::default(), recovery()).is_err());
    Ok(())
}

#[test]
fn recovery_rejects_an_active_hold_over_tombstoned_evidence() -> TestResult {
    let (mut s, w, source, _) = fixture()?;
    delete(&mut s, w)?;
    s.holds.insert("hold:forged".to_owned(), Hold { subject: source, witness: w, released_by: None });
    s.revision += 1;
    let bytes = raw_checkpoint(&s)?;
    assert!(RetentionStore::restore_checkpoint(&bytes, ContentDigest::sha256(&bytes), s.policy,
        s.custody(), RetentionLimits::default(), recovery()).is_err());
    Ok(())
}
