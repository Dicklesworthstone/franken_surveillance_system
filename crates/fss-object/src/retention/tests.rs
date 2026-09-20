#![forbid(unsafe_code)]

use super::*;
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;
fn rule(until: i128) -> RetentionRule {
    RetentionRule { retain_until: TimestampNs(until), reason: "rule:rolling-media".to_owned() }
}
fn budget(count: usize) -> RetentionBudget {
    RetentionBudget { max_objects: count, max_deleted_bytes: 1_000_000, max_staging_bytes: 1_000_000 }
}
fn store() -> RetentionStore {
    RetentionStore::new(ContentDigest::sha256(b"policy:v1"), ObjectLimits::new(128, 1_000_000),
        RetentionLimits::default())
}
fn grant(store: &RetentionStore, plan: &RetentionPlan, witness: ContentDigest) -> RetentionAuthorization {
    RetentionAuthorization { policy_digest: store.policy, plan_digest: plan.digest(), witness,
        permitted_objects: plan.selected().iter().copied().collect(),
        issued_at: TimestampNs(0), expires_at: TimestampNs(10_000) }
}
fn witness(store: &mut RetentionStore) -> Result<ContentDigest, RetentionError> {
    store.put_source(b"runtime-approved deletion authority", rule(20_000))
}

#[test]
fn retained_derivative_keeps_its_expired_sources() -> TestResult {
    let mut s = store();
    let source = s.put_source(b"source", rule(10))?;
    let derivative = s.put_derivative(b"embedding", rule(30), BTreeSet::from([source]))?;
    let before = s.state_digest()?;
    let plan = s.prepare_expiry(TimestampNs(20), budget(128))?;
    assert!(plan.selected().is_empty());
    assert_eq!(plan.blocked_due(), &BTreeSet::from([source]));
    assert_eq!(plan.not_due(), &BTreeSet::from([derivative]));
    assert_eq!(s.state_digest()?, before);
    Ok(())
}

#[test]
fn shared_sources_survive_expiry_of_only_one_parent() -> TestResult {
    let mut s = store(); let w = witness(&mut s)?;
    let source = s.put_source(b"shared", rule(1))?;
    let early = s.publish_manifest(ObjectManifest::new("early", [source], None)?, rule(10))?;
    let late = s.publish_manifest(ObjectManifest::new("late", [source], None)?, rule(100))?;
    let plan = s.prepare_expiry(TimestampNs(10), budget(128))?;
    assert_eq!(plan.selected(), &[early]);
    assert!(plan.blocked_due().contains(&source));
    let authority = grant(&s, &plan, w);
    let receipt = s.execute_expiry(&plan, &authority, TimestampNs(10))?;
    assert_eq!(receipt.deleted(), &[early]);
    s.custody().verify_closure(late)?;
    assert!(s.custody().is_tombstoned(early));
    Ok(())
}

#[test]
fn manifest_metadata_and_transitive_derivatives_are_real_dependencies() -> TestResult {
    let mut s = store();
    let source = s.put_source(b"source", rule(1))?;
    let metadata = s.put_source(b"provenance", rule(1))?;
    let crop = s.put_derivative(b"crop", rule(1), BTreeSet::from([source]))?;
    let embedding = s.put_derivative(b"embedding", rule(1), BTreeSet::from([crop]))?;
    let root = s.publish_manifest(ObjectManifest::new("event", [embedding], Some(metadata))?, rule(100))?;
    let plan = s.prepare_expiry(TimestampNs(20), budget(128))?;
    assert!(plan.selected().is_empty());
    assert_eq!(plan.blocked_due(), &BTreeSet::from([source, crop, embedding, metadata]));
    assert!(plan.not_due().contains(&root));
    Ok(())
}

#[test]
fn active_hold_pins_entire_graph_and_witness_until_explicit_release() -> TestResult {
    let mut s = store(); let w = witness(&mut s)?;
    let source = s.put_source(b"source", rule(1))?;
    let held = s.put_derivative(b"held", rule(2), BTreeSet::from([source]))?;
    let proof_source = s.put_source(b"hold proof source", rule(1))?;
    let proof = s.put_derivative(b"hold proof", rule(1), BTreeSet::from([proof_source]))?;
    let before = s.state_digest()?;
    s.add_hold(before, "hold:case", held, proof)?;
    let plan = s.prepare_expiry(TimestampNs(30), budget(128))?;
    assert!(plan.selected().is_empty());
    assert_eq!(plan.held_roots(), &BTreeSet::from([held, proof]));
    assert_eq!(plan.blocked_due().len(), 4);
    let current = s.state_digest()?;
    s.release_hold(current, "hold:case", w)?;
    let plan = s.prepare_expiry(TimestampNs(30), budget(128))?;
    assert_eq!(plan.selected().len(), 4);
    assert!(matches!(s.add_hold(s.state_digest()?, "hold:case", held, proof), Err(RetentionError::HoldConflict)));
    Ok(())
}

#[test]
fn bounded_batches_delete_dependents_before_sources_without_dangling_roots() -> TestResult {
    let mut s = store(); let w = witness(&mut s)?;
    let source = s.put_source(b"source", rule(1))?;
    let derivative = s.put_derivative(b"derived", rule(1), BTreeSet::from([source]))?;
    let root = s.publish_manifest(ObjectManifest::new("event", [derivative], None)?, rule(1))?;
    for expected in [root, derivative, source] {
        let plan = s.prepare_expiry(TimestampNs(10), budget(1))?;
        assert_eq!(plan.selected(), &[expected]);
        let authority = grant(&s, &plan, w);
        let receipt = s.execute_expiry(&plan, &authority, TimestampNs(10))?;
        assert_eq!(receipt.after_state(), s.state_digest()?);
        s.verify_live_graph()?;
    }
    assert!(s.prepare_expiry(TimestampNs(10), budget(1))?.selected().is_empty());
    assert_eq!(s.custody().total_bytes(), s.custody().read_verified(w)?.len() as u64);
    Ok(())
}

#[test]
fn byte_limited_skip_never_deletes_the_skipped_nodes_source() -> TestResult {
    let mut s = store();
    let source = s.put_source(b"s", rule(1))?;
    let large = s.put_derivative(&[9; 100], rule(1), BTreeSet::from([source]))?;
    let small = s.put_source(b"x", rule(1))?;
    let plan = s.prepare_expiry(TimestampNs(10), RetentionBudget {
        max_deleted_bytes: 2, ..budget(128)
    })?;
    assert_eq!(plan.selected(), &[small]);
    assert_eq!(plan.deferred_due(), &BTreeSet::from([source, large]));
    Ok(())
}

#[test]
fn exact_deadline_and_zero_budget_have_explicit_results() -> TestResult {
    let mut s = store(); let source = s.put_source(b"source", rule(10))?;
    assert!(s.prepare_expiry(TimestampNs(9), budget(1))?.selected().is_empty());
    assert_eq!(s.prepare_expiry(TimestampNs(10), budget(1))?.selected(), &[source]);
    let plan = s.prepare_expiry(TimestampNs(10), budget(0))?;
    assert!(plan.selected().is_empty());
    assert_eq!(plan.deferred_due(), &BTreeSet::from([source]));
    Ok(())
}

#[test]
fn registration_is_idempotent_but_never_rewrites_retention_or_dependencies() -> TestResult {
    let mut s = store(); let source = s.put_source(b"source", rule(10))?;
    let before = s.state_digest()?;
    assert_eq!(s.put_source(b"source", rule(10))?, source);
    assert_eq!(s.state_digest()?, before);
    assert!(matches!(s.put_source(b"source", rule(1)), Err(RetentionError::ConflictingRegistration)));
    assert!(s.put_derivative(b"derived", rule(1), BTreeSet::from([ContentDigest::sha256(b"absent")])).is_err());
    assert_eq!(s.state_digest()?, before);
    assert_eq!(s.custody().object_count(), 1);
    Ok(())
}

#[test]
fn opaque_manifest_bytes_cannot_be_promoted_without_dependency_registration() -> TestResult {
    let mut s = store(); let source = s.put_source(b"source", rule(1))?;
    let manifest = ObjectManifest::new("event", [source], None)?;
    s.put_source(&manifest.canonical_bytes(), rule(1))?;
    assert!(matches!(s.publish_manifest(manifest, rule(1)), Err(RetentionError::ConflictingRegistration)));
    Ok(())
}

#[test]
fn new_hold_or_new_parent_invalidates_a_prepared_plan() -> TestResult {
    for hold in [false, true] {
        let mut s = store(); let w = witness(&mut s)?;
        let source = s.put_source(b"source", rule(1))?;
        let plan = s.prepare_expiry(TimestampNs(10), budget(128))?;
        let authority = grant(&s, &plan, w);
        if hold { s.add_hold(s.state_digest()?, "hold:new", source, w)?; }
        else { s.put_derivative(b"new dependent", rule(100), BTreeSet::from([source]))?; }
        let before = s.state_digest()?; let bytes = s.custody().total_bytes();
        assert!(matches!(s.execute_expiry(&plan, &authority, TimestampNs(10)), Err(RetentionError::StalePlan)));
        assert_eq!(s.state_digest()?, before); assert_eq!(s.custody().total_bytes(), bytes);
        s.custody().read_verified(source)?;
    }
    Ok(())
}

#[test]
fn projected_authority_policy_scope_and_lease_are_enforced_before_mutation() -> TestResult {
    for fault in 0..5 {
        let mut s = store(); let w = witness(&mut s)?;
        let source = s.put_source(b"source", rule(1))?;
        let plan = s.prepare_expiry(TimestampNs(10), budget(128))?;
        let mut authority = grant(&s, &plan, w);
        match fault {
            0 => authority.policy_digest = ContentDigest::sha256(b"wrong policy"),
            1 => authority.plan_digest = ContentDigest::sha256(b"wrong plan"),
            2 => authority.permitted_objects.clear(),
            3 => authority.expires_at = TimestampNs(10),
            _ => authority.witness = source,
        }
        let before = s.state_digest()?;
        assert!(matches!(s.execute_expiry(&plan, &authority, TimestampNs(10)), Err(RetentionError::Unauthorized)));
        assert_eq!(s.state_digest()?, before); s.custody().read_verified(source)?;
    }
    Ok(())
}

#[test]
fn custody_corruption_and_staging_budget_return_no_partial_deletion() -> TestResult {
    for corrupt in [false, true] {
        let mut s = store(); let w = witness(&mut s)?;
        let a = s.put_source(b"a", rule(1))?; let b = s.put_source(b"b", rule(1))?;
        let mut limits = budget(128);
        if !corrupt { limits.max_staging_bytes = 0; }
        let plan = s.prepare_expiry(TimestampNs(10), limits)?;
        let authority = grant(&s, &plan, w);
        if corrupt { s.custody.corrupt_for_test(b)?; }
        let before = s.state_digest()?; let bytes = s.custody().total_bytes();
        assert!(s.execute_expiry(&plan, &authority, TimestampNs(10)).is_err());
        assert_eq!(s.state_digest()?, before); assert_eq!(s.custody().total_bytes(), bytes);
        assert!(!s.custody().is_tombstoned(a)); assert!(!s.custody().is_tombstoned(b));
        assert!(s.receipts.is_empty());
    }
    Ok(())
}

#[test]
fn exact_retry_preserves_receipt_and_cannot_resurrect_payload() -> TestResult {
    let mut s = store(); let w = witness(&mut s)?;
    let source = s.put_source(b"source", rule(1))?;
    let plan = s.prepare_expiry(TimestampNs(10), budget(128))?;
    let authority = grant(&s, &plan, w);
    let first = s.execute_expiry(&plan, &authority, TimestampNs(10))?;
    let after = s.state_digest()?;
    assert_eq!(s.execute_expiry(&plan, &authority, TimestampNs(11))?, first);
    assert_eq!(s.state_digest()?, after);
    assert!(s.put_source(b"source", rule(1)).is_err());
    assert!(s.put_derivative(b"resurrection", rule(20), BTreeSet::from([source])).is_err());
    assert!(s.custody().read_verified(source).is_err());
    assert_eq!(s.receipts.len(), 1);
    Ok(())
}

#[test]
fn clock_regression_and_resealed_selection_are_refused() -> TestResult {
    let mut s = store(); let w = witness(&mut s)?;
    s.put_source(b"source", rule(1))?;
    let plan = s.prepare_expiry(TimestampNs(10), budget(128))?;
    let authority = grant(&s, &plan, w);
    assert!(matches!(s.execute_expiry(&plan, &authority, TimestampNs(9)), Err(RetentionError::ClockRegression)));
    let mut forged = plan.clone(); forged.selected.clear(); forged.digest = forged.computed_digest()?;
    let forged_authority = grant(&s, &forged, w);
    assert!(matches!(s.execute_expiry(&forged, &forged_authority, TimestampNs(10)), Err(RetentionError::StalePlan)));
    s.execute_expiry(&plan, &authority, TimestampNs(10))?;
    assert!(matches!(s.prepare_expiry(TimestampNs(9), budget(1)), Err(RetentionError::ClockRegression)));
    Ok(())
}

#[test]
fn entry_edge_hold_and_receipt_ceilings_do_not_evict_protection() -> TestResult {
    let mut s = RetentionStore::new(ContentDigest::sha256(b"p"), ObjectLimits::new(128, 1_000_000),
        RetentionLimits { max_entries: 2, max_edges: 0, max_holds: 0, max_receipts: 0 });
    let w = witness(&mut s)?; let source = s.put_source(b"source", rule(1))?;
    assert!(matches!(s.put_source(b"overflow", rule(1)), Err(RetentionError::CapacityExceeded)));
    assert!(matches!(s.add_hold(s.state_digest()?, "hold:x", source, w), Err(RetentionError::CapacityExceeded)));
    let plan = s.prepare_expiry(TimestampNs(10), budget(128))?;
    let authority = grant(&s, &plan, w); let before = s.state_digest()?;
    assert!(matches!(s.execute_expiry(&plan, &authority, TimestampNs(10)), Err(RetentionError::CapacityExceeded)));
    assert_eq!(s.state_digest()?, before); s.custody().read_verified(source)?;
    let mut t = RetentionStore::new(ContentDigest::sha256(b"p"), ObjectLimits::default(),
        RetentionLimits { max_edges: 0, ..RetentionLimits::default() });
    let source = t.put_source(b"source", rule(1))?;
    assert!(matches!(t.put_derivative(b"derived", rule(1), BTreeSet::from([source])), Err(RetentionError::CapacityExceeded)));
    assert_eq!(t.custody().object_count(), 1);
    Ok(())
}

#[test]
fn unregistered_custody_mutation_is_not_silently_adopted() -> TestResult {
    let mut s = store(); s.put_source(b"source", rule(1))?;
    // Only test code in this private module can violate the owner's no-mutable-escape rule.
    s.custody.put_verified(b"untracked object")?;
    assert!(matches!(s.prepare_expiry(TimestampNs(10), budget(128)), Err(RetentionError::InvalidRecord)));
    Ok(())
}

#[test]
fn independent_insertion_order_produces_identical_state_and_plan() -> TestResult {
    let mut a = store(); let mut b = store();
    for bytes in [b"a".as_slice(), b"b", b"c"] { a.put_source(bytes, rule(1))?; }
    for bytes in [b"c".as_slice(), b"a", b"b"] { b.put_source(bytes, rule(1))?; }
    assert_eq!(a.state_digest()?, b.state_digest()?);
    assert_eq!(a.prepare_expiry(TimestampNs(10), budget(2))?, b.prepare_expiry(TimestampNs(10), budget(2))?);
    Ok(())
}

#[test]
fn exhaustive_small_dags_preserve_every_unselected_objects_dependencies() -> TestResult {
    // Every labelled acyclic graph on four insertion-ordered nodes (six possible edges),
    // every deadline mask, and all five count budgets. No random seed or external model oracle.
    for edges in 0_u32..64 {
        for deadlines in 0_u32..16 {
            let mut s = store(); let mut nodes = Vec::new(); let mut bit = 0;
            for node in 0..4 {
                let mut dependencies = BTreeSet::new();
                for source in nodes.iter().take(node) {
                    if edges & (1 << bit) != 0 { dependencies.insert(*source); }
                    bit += 1;
                }
                let until = if deadlines & (1 << node) == 0 { 1 } else { 100 };
                let bytes = [node as u8];
                nodes.push(if dependencies.is_empty() { s.put_source(&bytes, rule(until))? }
                    else { s.put_derivative(&bytes, rule(until), dependencies)? });
            }
            for count in 0..5 {
                let plan = s.prepare_expiry(TimestampNs(10), budget(count))?;
                let selected: BTreeSet<_> = plan.selected().iter().copied().collect();
                assert!(selected.len() <= count);
                for (digest, entry) in &s.entries {
                    if !selected.contains(digest) {
                        assert!(entry.dependencies.is_disjoint(&selected), "edges={edges} deadlines={deadlines} count={count}");
                    }
                }
            }
        }
    }
    Ok(())
}
