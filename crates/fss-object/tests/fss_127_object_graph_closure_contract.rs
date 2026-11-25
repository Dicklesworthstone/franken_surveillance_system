#![forbid(unsafe_code)]
//! Contract and fault suite for `FSS-127` (`fss-x4a.13.11`):
//! Deterministic ATP object-graph closure verifier with authority-before-expansion,
//! non-collapsed custody floors, bottom-up canonical post-order, and hostile wire refusal.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::json_input::{Value, parse};
use fss_core::{ContentDigest, Generation, ObjectId, TombstoneReason, TombstoneRecord};
use fss_object::closure::{
    AtpArchiveGraphCatalog, CLOSURE_WITNESS_VERSION, ClosureAuthorityContext, ClosureBudget,
    ClosureDefectKind, ClosureEdge, ClosureEdgeKind, ClosureError, ClosureRecoveryGuidance,
    ClosureVerdict, ClosureVerificationWitness, ClosureVerifier, CustodyLevel, InspectedObject,
    MAX_CLOSURE_WITNESS_WIRE_BYTES, ObjectGraphSource,
};
use fss_object::{InMemoryObjectStore, ObjectLimits, ObjectManifest};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn d(label: &str) -> ContentDigest {
    ContentDigest::sha256(label.as_bytes())
}

#[test]
fn in_memory_store_closure_produces_bottom_up_witness_and_detects_tombstone_and_corruption()
-> TestResult {
    let mut store = InMemoryObjectStore::new(ObjectLimits::default());
    let leaf_a = store.put_verified(b"camera-segment-frame-a")?;
    let leaf_b = store.put_verified(b"camera-segment-frame-b")?;
    let meta = store.put_verified(b"segment-metadata-v1")?;

    let sub = ObjectManifest::new("fss.segment.v1", [leaf_a, leaf_b], Some(meta))?;
    let sub_root = store.publish_manifest(sub)?.root;

    let leaf_c = store.put_verified(b"camera-audio-chunk-c")?;
    let top = ObjectManifest::new("fss.clip.v1", [sub_root, leaf_c], None)?;
    let top_root = store.publish_manifest(top)?.root;

    let auth = ClosureAuthorityContext::active_all_edges(d("basis-127"), 3, 2);
    let witness = ClosureVerifier::verify_closure(
        &store,
        top_root,
        &auth,
        CustodyLevel::Verified,
        ClosureBudget::DEFAULT,
        |_| false,
    )?;
    assert!(witness.is_complete());
    assert_eq!(witness.verdict, ClosureVerdict::VerifiedComplete);
    assert_eq!(
        witness.guidance,
        ClosureRecoveryGuidance::ReadyForRootPublication
    );
    assert_eq!(witness.ordered_members.len(), 6);
    assert_eq!(witness.edge_count, 5);
    assert_eq!(witness.max_observed_depth, 2);

    // Bottom-up post-order guarantee: every child strictly precedes its parent!
    let pos: BTreeMap<ContentDigest, usize> = witness
        .ordered_members
        .iter()
        .enumerate()
        .map(|(i, m)| (m.digest, i))
        .collect();
    assert!(pos[&leaf_a] < pos[&sub_root]);
    assert!(pos[&leaf_b] < pos[&sub_root]);
    assert!(pos[&meta] < pos[&sub_root]);
    assert!(pos[&sub_root] < pos[&top_root]);
    assert!(pos[&leaf_c] < pos[&top_root]);
    assert_eq!(
        witness.ordered_members.last().map(|m| m.digest),
        Some(top_root)
    );

    // Witness binary codec round-trip + JSONL log check.
    let wire = witness.to_canonical_bytes()?;
    let decoded = ClosureVerificationWitness::from_canonical_bytes(&wire)?;
    assert_eq!(decoded, witness);
    let line = witness.to_jsonl_line(
        "fss127_in_memory",
        42,
        "scripts/e2e/fss_127_object_graph_closure.sh",
    );
    let parsed = parse(&line)?;
    let obj = parsed.object().ok_or("jsonl object")?;
    assert_eq!(
        obj.get("verdict").and_then(Value::text),
        Some("verified_complete")
    );
    assert_eq!(obj.get("verifiedNodes").and_then(Value::integer), Some(6));

    // Requiring `Durable` on an in-memory `Visible`/`Verified` store fails honestly as Incomplete
    // (never collapses Verified/Visible into Durable).
    let below = ClosureVerifier::verify_closure(
        &store,
        top_root,
        &auth,
        CustodyLevel::Durable,
        ClosureBudget::DEFAULT,
        |_| false,
    )?;
    assert!(!below.is_complete());
    assert_eq!(below.verdict, ClosureVerdict::Incomplete);
    assert!(
        below
            .defects
            .iter()
            .any(|def| def.kind == ClosureDefectKind::BelowCustodyFloor)
    );

    // Corrupting a leaf triggers CorruptOrInvalidated while still preserving verified siblings!
    let mut corrupt_store = store.clone();
    corrupt_store.corrupt_for_test(leaf_a)?;
    let corrupt_w = ClosureVerifier::verify_closure(
        &corrupt_store,
        top_root,
        &auth,
        CustodyLevel::Verified,
        ClosureBudget::DEFAULT,
        |_| false,
    )?;
    assert_eq!(corrupt_w.verdict, ClosureVerdict::CorruptOrInvalidated);
    assert_eq!(
        corrupt_w.guidance,
        ClosureRecoveryGuidance::QuarantineAndRepairCorruptGraph
    );
    assert!(
        corrupt_w
            .defects
            .iter()
            .any(|def| def.digest == leaf_a && def.kind == ClosureDefectKind::Corrupt)
    );
    // Sibling leaf_c remained verified and preserved as partial valid evidence!
    assert!(corrupt_w.ordered_members.iter().any(|m| m.digest == leaf_c));

    // Tombstoning leaf_b invalidates sub_root and top_root -> CorruptOrInvalidated.
    let del_witness = store.put_verified(b"deletion-authority-proof")?;
    let prior_gen = Generation::parse_positive(1)?;
    let tomb_gen = prior_gen.next()?;
    store.tombstone(
        leaf_b,
        TombstoneRecord::new(
            ObjectId::parse("obj:fss127-leaf-b")?,
            tomb_gen,
            prior_gen,
            TombstoneReason::Deleted,
            Some(del_witness),
            leaf_b,
        )?,
    )?;
    let tomb_w = ClosureVerifier::verify_closure(
        &store,
        top_root,
        &auth,
        CustodyLevel::Verified,
        ClosureBudget::DEFAULT,
        |_| false,
    )?;
    assert_eq!(tomb_w.verdict, ClosureVerdict::CorruptOrInvalidated);
    assert!(
        tomb_w
            .defects
            .iter()
            .any(|def| def.kind == ClosureDefectKind::InvalidatedManifest)
    );

    emit_caplog(
        "fss127_in_memory_bottom_up_tombstone_corrupt",
        "bottom_up_post_order_non_collapse_and_defects_verified",
        "bottom_up_post_order_non_collapse_and_defects_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn multi_tier_archive_edges_authority_before_expansion_cycles_cancel_and_wire_hostility()
-> TestResult {
    let root = d("archive-root");
    let child_derived = d("child-derived");
    let child_cache = d("child-cache");
    let child_replica = d("child-replica");
    let child_journal = d("child-journal");
    let secret_leaf = d("restricted-leaf");

    // 1. Multi-tier Retrievable graph traversing Derived, Cache, Replica, and Journal edges.
    let mut catalog = AtpArchiveGraphCatalog::new();
    catalog.insert(
        root,
        InspectedObject::Present {
            custody: CustodyLevel::Retrievable,
            byte_len: 512,
            post_repair_verified: false,
            edges: vec![
                ClosureEdge {
                    kind: ClosureEdgeKind::Derived,
                    target: child_derived,
                },
                ClosureEdge {
                    kind: ClosureEdgeKind::Cache,
                    target: child_cache,
                },
                ClosureEdge {
                    kind: ClosureEdgeKind::Replica,
                    target: child_replica,
                },
                ClosureEdge {
                    kind: ClosureEdgeKind::Journal,
                    target: child_journal,
                },
            ],
        },
    );
    for (dig, repaired) in [
        (child_derived, false),
        (child_cache, true),
        (child_replica, false),
        (child_journal, false),
    ] {
        catalog.insert(
            dig,
            InspectedObject::Present {
                custody: CustodyLevel::Retrievable,
                byte_len: 1024,
                post_repair_verified: repaired,
                edges: Vec::new(),
            },
        );
    }

    let auth = ClosureAuthorityContext::active_all_edges(d("basis-archive"), 7, 4);
    let ok_w = ClosureVerifier::verify_closure(
        &catalog,
        root,
        &auth,
        CustodyLevel::Retrievable,
        ClosureBudget::DEFAULT,
        |_| false,
    )?;
    assert!(ok_w.is_complete());
    assert_eq!(ok_w.ordered_members.len(), 5);
    assert_eq!(ok_w.total_verified_bytes, 512 + 4 * 1024);
    assert!(
        ok_w.ordered_members
            .iter()
            .any(|m| m.digest == child_cache && m.post_repair_verified)
    );

    // 2. AUTHORITY-BEFORE-EXPANSION proof: wrap catalog in a spy that panics if `secret_leaf` is
    //    ever inspected! Restricted objects MUST be blocked BEFORE `inspect_object` is called!
    struct SpyNoRestrictedInspect<'a> {
        inner: &'a AtpArchiveGraphCatalog,
        forbidden: ContentDigest,
    }
    impl ObjectGraphSource for SpyNoRestrictedInspect<'_> {
        fn inspect_object(&self, digest: ContentDigest) -> InspectedObject {
            assert_ne!(
                digest, self.forbidden,
                "authority-before-expansion violated: inspected restricted object!"
            );
            self.inner.inspect_object(digest)
        }
    }
    let mut restricted_catalog = catalog.clone();
    restricted_catalog.insert(
        child_derived,
        InspectedObject::Present {
            custody: CustodyLevel::Retrievable,
            byte_len: 1024,
            post_repair_verified: false,
            edges: vec![ClosureEdge {
                kind: ClosureEdgeKind::Derived,
                target: secret_leaf,
            }],
        },
    );
    let mut restricted_auth = auth.clone();
    restricted_auth.restricted_objects.insert(secret_leaf);
    let spy = SpyNoRestrictedInspect {
        inner: &restricted_catalog,
        forbidden: secret_leaf,
    };
    let unauth_w = ClosureVerifier::verify_closure(
        &spy,
        root,
        &restricted_auth,
        CustodyLevel::Retrievable,
        ClosureBudget::DEFAULT,
        |_| false,
    )?;
    assert_eq!(unauth_w.verdict, ClosureVerdict::Unauthorized);
    assert_eq!(
        unauth_w.guidance,
        ClosureRecoveryGuidance::ReauthorizeOrPruneRestrictedSubgraph
    );
    assert!(
        unauth_w.defects.iter().any(|def| def.digest == secret_leaf
            && def.kind == ClosureDefectKind::UnauthorizedOrRedacted)
    );

    // 3. Disallowed edge class fails closed without inspecting target.
    let mut no_cache_auth = auth.clone();
    no_cache_auth
        .allowed_edge_kinds
        .remove(&ClosureEdgeKind::Cache);
    let edge_w = ClosureVerifier::verify_closure(
        &catalog,
        root,
        &no_cache_auth,
        CustodyLevel::Retrievable,
        ClosureBudget::DEFAULT,
        |_| false,
    )?;
    assert_eq!(edge_w.verdict, ClosureVerdict::Unauthorized);

    // 4. Revoked capability, revoked privacy, stale generation, invalid floor, and invalid budget.
    let mut revoked = auth.clone();
    revoked.capability_active = false;
    assert!(matches!(
        ClosureVerifier::verify_closure(
            &catalog,
            root,
            &revoked,
            CustodyLevel::Verified,
            ClosureBudget::DEFAULT,
            |_| false
        ),
        Err(ClosureError::AuthorityRevoked { .. })
    ));
    let mut stale_gen = auth.clone();
    stale_gen.authority_generation = 99;
    assert!(matches!(
        ClosureVerifier::verify_closure(
            &catalog,
            root,
            &stale_gen,
            CustodyLevel::Verified,
            ClosureBudget::DEFAULT,
            |_| false
        ),
        Err(ClosureError::StaleGeneration {
            expected: 7,
            observed: 99
        })
    ));
    assert_eq!(
        ClosureVerifier::verify_closure(
            &catalog,
            root,
            &auth,
            CustodyLevel::Staged,
            ClosureBudget::DEFAULT,
            |_| false
        ),
        Err(ClosureError::InvalidCustodyFloor)
    );
    assert_eq!(
        ClosureBudget::new(0, 10, 4, 1024),
        Err(ClosureError::InvalidBudget)
    );

    // 5. Indeterminate custody never upgrades to VerifiedComplete.
    let mut indet_cat = catalog.clone();
    indet_cat.insert(
        child_replica,
        InspectedObject::Indeterminate {
            reason: "s3_list_lagging_consistency".to_owned(),
        },
    );
    let indet_w = ClosureVerifier::verify_closure(
        &indet_cat,
        root,
        &auth,
        CustodyLevel::Retrievable,
        ClosureBudget::DEFAULT,
        |_| false,
    )?;
    assert_eq!(indet_w.verdict, ClosureVerdict::Indeterminate);
    assert_eq!(
        indet_w.guidance,
        ClosureRecoveryGuidance::ReconcileIndeterminateCustody
    );

    // 6. Directed cycle fails closed as CorruptOrInvalidated without infinite loop.
    let mut cyclic = catalog.clone();
    cyclic.insert(
        child_journal,
        InspectedObject::Present {
            custody: CustodyLevel::Retrievable,
            byte_len: 1024,
            post_repair_verified: false,
            edges: vec![ClosureEdge {
                kind: ClosureEdgeKind::Journal,
                target: root,
            }],
        },
    );
    let cyc_w = ClosureVerifier::verify_closure(
        &cyclic,
        root,
        &auth,
        CustodyLevel::Retrievable,
        ClosureBudget::DEFAULT,
        |_| false,
    )?;
    assert_eq!(cyc_w.verdict, ClosureVerdict::CorruptOrInvalidated);
    assert!(
        cyc_w
            .defects
            .iter()
            .any(|def| def.kind == ClosureDefectKind::CycleDetected)
    );

    // 7. Tight node budget and cooperative cancellation halt cleanly without false completeness.
    let tiny_budget = ClosureBudget::new(2, 16, 8, 1024 * 1024)?;
    let bud_w = ClosureVerifier::verify_closure(
        &catalog,
        root,
        &auth,
        CustodyLevel::Retrievable,
        tiny_budget,
        |_| false,
    )?;
    assert_eq!(bud_w.verdict, ClosureVerdict::BudgetExceeded);
    assert_eq!(
        bud_w.guidance,
        ClosureRecoveryGuidance::RaiseTraversalBudget
    );

    let cancel_w = ClosureVerifier::verify_closure(
        &catalog,
        root,
        &auth,
        CustodyLevel::Retrievable,
        ClosureBudget::DEFAULT,
        |step| step >= 3,
    )?;
    assert_eq!(cancel_w.verdict, ClosureVerdict::Cancelled);
    assert_eq!(
        cancel_w.guidance,
        ClosureRecoveryGuidance::RetryFromCleanState
    );

    // 8. Hostile witness wire bytes fail closed (bad magic, bad version, truncation, checksum flip,
    //    trailing bytes, alloc-bomb count, oversize buffer).
    let wire = ok_w.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        ClosureVerificationWitness::from_canonical_bytes(&bad_magic),
        Err(ClosureError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&(CLOSURE_WITNESS_VERSION + 1).to_be_bytes());
    assert_eq!(
        ClosureVerificationWitness::from_canonical_bytes(&bad_ver),
        Err(ClosureError::UnsupportedVersion {
            version: CLOSURE_WITNESS_VERSION + 1
        })
    );
    assert!(matches!(
        ClosureVerificationWitness::from_canonical_bytes(&wire[..wire.len() - 5]),
        Err(ClosureError::MalformedWire(_))
    ));
    let mut flipped = wire.clone();
    let end = flipped.len() - 1;
    flipped[end] ^= 0x55;
    assert_eq!(
        ClosureVerificationWitness::from_canonical_bytes(&flipped),
        Err(ClosureError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0x99);
    assert!(matches!(
        ClosureVerificationWitness::from_canonical_bytes(&trailing),
        Err(ClosureError::MalformedWire(_))
    ));
    let huge = vec![0u8; MAX_CLOSURE_WITNESS_WIRE_BYTES + 1];
    assert!(matches!(
        ClosureVerificationWitness::from_canonical_bytes(&huge),
        Err(ClosureError::BoundsExceeded { .. })
    ));

    // Self-contradictory resealed witness (VerifiedComplete with non-empty defects) fails closed
    // at serialization time AND at cold wire decode time.
    let mut forged = indet_w.clone();
    forged.verdict = ClosureVerdict::VerifiedComplete;
    forged.witness_digest = forged.compute_digest()?;
    assert!(matches!(
        forged.to_canonical_bytes(),
        Err(ClosureError::MalformedWire(_))
    ));
    assert!(matches!(
        forged.verify_invariants(),
        Err(ClosureError::MalformedWire(_))
    ));

    // Unvalidated struct-literal ClosureBudget cannot bypass hard ceilings in verify_closure.
    let forged_budget = ClosureBudget {
        max_nodes: 0,
        max_edges: 0,
        max_depth: 0,
        max_bytes: 0,
    };
    assert_eq!(
        ClosureVerifier::verify_closure(
            &catalog,
            root,
            &auth,
            CustodyLevel::Verified,
            forged_budget,
            |_| false,
        ),
        Err(ClosureError::InvalidBudget)
    );

    // Forged downgraded verdict (Corrupt/Cycle defect resealed as Incomplete) fails closed.
    let mut downgraded = cyc_w;
    downgraded.verdict = ClosureVerdict::Incomplete;
    downgraded.guidance = ClosureRecoveryGuidance::WaitForMissingOrStagedChildren;
    downgraded.witness_digest = downgraded.compute_digest()?;
    assert!(matches!(
        downgraded.to_canonical_bytes(),
        Err(ClosureError::MalformedWire(_))
    ));

    // Forged total_verified_bytes mismatch fails closed.
    let mut bad_bytes = ok_w;
    bad_bytes.total_verified_bytes = bad_bytes.total_verified_bytes.saturating_add(1);
    bad_bytes.witness_digest = bad_bytes.compute_digest()?;
    assert!(matches!(
        bad_bytes.to_canonical_bytes(),
        Err(ClosureError::MalformedWire(_))
    ));

    // Verify BTreeSet deduplication on duplicate catalog edges stays deterministic.
    let edge_set: BTreeSet<ClosureEdge> = [
        ClosureEdge {
            kind: ClosureEdgeKind::Derived,
            target: child_derived,
        },
        ClosureEdge {
            kind: ClosureEdgeKind::Derived,
            target: child_derived,
        },
    ]
    .into_iter()
    .collect();
    assert_eq!(edge_set.len(), 1);

    emit_caplog(
        "fss127_archive_edges_auth_cycles_cancel_wire",
        "all_multi_tier_auth_fault_and_wire_checks_passed",
        "all_multi_tier_auth_fault_and_wire_checks_passed",
        "pass",
    );
    Ok(())
}
