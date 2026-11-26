#![forbid(unsafe_code)]
//! Contract & fault tests for `FSS-133` (`fss-x4a.13.17`): graph-complete archive deletion
//! traversal (`docs/ATP_ARCHIVE_AND_REPLICATION.md` §10).

use std::collections::BTreeSet;

use fss_core::{ContentDigest, TimestampNs};
use fss_object::closure::CustodyLevel;
use fss_object::deletion_closure::{
    ATP_DELETION_CLOSURE_PLAN_DOMAIN, ATP_DELETION_CLOSURE_RECEIPT_DOMAIN, ArchiveDeletionCatalog,
    DELETION_RECEIPT_MAGIC, DELETION_RECEIPT_VERSION, DeletionArtifactClass,
    DeletionAuthorityContext, DeletionClosureError, DeletionClosureExecutor,
    DeletionClosureReceipt, DeletionClosureState, DeletionGraphNode, DeletionGuidance,
    UnknownExternalCopy,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn d(label: &str) -> ContentDigest {
    ContentDigest::sha256(label.as_bytes())
}

fn node(
    digest: ContentDigest,
    class: DeletionArtifactClass,
    byte_len: u64,
    deps: &[ContentDigest],
) -> DeletionGraphNode {
    DeletionGraphNode {
        digest,
        class,
        byte_len,
        custody: CustodyLevel::Durable,
        active_holds: BTreeSet::new(),
        dependencies: deps.iter().copied().collect(),
        hidden_reference_aliases: BTreeSet::new(),
        reachable: true,
        simulate_surviving_hidden_ref: None,
    }
}

#[test]
fn nine_class_complete_deletion_tombstone_unreachability_and_external_copy_honesty() -> TestResult {
    // Build a complete graph exercising ALL 9 normative artifact classes from §10!
    let d_src = d("source-chunk-1");
    let d_deriv = d("derivative-thumb-1");
    let d_repair = d("raptorq-repair-sym-1");
    let d_local_rep = d("local-spool-replica-1");
    let d_remote_rep = d("s3-remote-replica-1");
    let d_index = d("search-embedding-index-1");
    let d_journal = d("atp-transfer-journal-1");
    let d_bundle = d("exported-bundle-in-custody-1");
    let d_root = d("archive-manifest-root-1");

    let mut catalog = ArchiveDeletionCatalog::new();
    catalog.insert(node(d_src, DeletionArtifactClass::SourceChunk, 4_096, &[]));
    catalog.insert(node(
        d_deriv,
        DeletionArtifactClass::DerivativeChunk,
        512,
        &[d_src],
    ));
    catalog.insert(node(
        d_repair,
        DeletionArtifactClass::RepairSymbol,
        1_024,
        &[d_src],
    ));
    catalog.insert(node(
        d_local_rep,
        DeletionArtifactClass::LocalReplica,
        4_096,
        &[d_src],
    ));
    catalog.insert(node(
        d_remote_rep,
        DeletionArtifactClass::RemoteReplica,
        4_096,
        &[d_src],
    ));
    catalog.insert(node(
        d_index,
        DeletionArtifactClass::IndexOrCache,
        256,
        &[d_deriv],
    ));
    catalog.insert(node(
        d_journal,
        DeletionArtifactClass::TransferJournalOrStaging,
        128,
        &[d_remote_rep],
    ));
    catalog.insert(node(
        d_bundle,
        DeletionArtifactClass::ExportedBundleInCustody,
        2_048,
        &[d_src, d_deriv],
    ));
    catalog.insert(node(
        d_root,
        DeletionArtifactClass::Manifest,
        640,
        &[
            d_src,
            d_deriv,
            d_repair,
            d_local_rep,
            d_remote_rep,
            d_index,
            d_journal,
            d_bundle,
        ],
    ));

    let basis = d("basis:del-seq-50");
    let approval = d("owner-approval:del-root-1");
    let auth = DeletionAuthorityContext::approved(basis, 3, 2, approval);
    let external_copies = vec![UnknownExternalCopy {
        copy_id: "ext:usb-2026-10".to_owned(),
        destination_label: "offline-usb-export".to_owned(),
        note: "exported outside FSS custody; deletion cannot be verified".to_owned(),
    }];

    let plan = DeletionClosureExecutor::plan_closure(
        &catalog,
        d_root,
        &auth,
        external_copies.clone(),
        TimestampNs(10_000),
        false,
    )?;
    assert!(!plan.is_blocked());
    assert_eq!(plan.members.len(), 9);
    assert_eq!(
        plan.total_planned_bytes,
        4_096 + 512 + 1_024 + 4_096 + 4_096 + 256 + 128 + 2_048 + 640
    );
    assert_eq!(plan.unknown_external_copies, external_copies);
    assert_eq!(
        ATP_DELETION_CLOSURE_PLAN_DOMAIN,
        "fss.atp_deletion_closure_plan.v1"
    );
    assert_eq!(
        ATP_DELETION_CLOSURE_RECEIPT_DOMAIN,
        "fss.atp_deletion_closure_receipt.v1"
    );

    let receipt = DeletionClosureExecutor::execute_and_verify(
        &mut catalog,
        &plan,
        &auth,
        &BTreeSet::new(),
        TimestampNs(11_000),
        false,
    )?;
    assert_eq!(receipt.state, DeletionClosureState::UnreachabilityVerified);
    assert_eq!(receipt.deleted_digests.len(), 9);
    assert!(receipt.indeterminate_digests.is_empty());
    assert!(receipt.surviving_hidden_references.is_empty());
    assert!(receipt.tombstone_root_digest.is_some());
    assert_eq!(
        catalog.tombstone_for(&d_root),
        receipt.tombstone_root_digest
    );
    // Unknown external copies remain explicitly disclosed (NEVER claimed deleted!).
    assert_eq!(receipt.unknown_external_copies, external_copies);

    // Every member in FSS custody is now unreachable.
    for m in &plan.members {
        assert!(!catalog.get(&m.digest).expect("node tracked").reachable);
    }

    // Wire codec round-trip (`FSSDCL01` v1).
    let wire = receipt.to_canonical_bytes()?;
    assert_eq!(&wire[..8], &DELETION_RECEIPT_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]),
        DELETION_RECEIPT_VERSION
    );
    assert_eq!(
        DeletionClosureReceipt::from_canonical_bytes(&wire)?,
        receipt
    );

    emit_caplog(
        "fss133_nine_class_deletion_tombstone_and_external_honesty",
        "all_9_classes_tombstoned_unreachability_verified_external_preserved",
        "all_9_classes_tombstoned_unreachability_verified_external_preserved",
        "pass",
    );
    Ok(())
}

#[test]
fn holds_shared_parents_hidden_ref_leaks_indeterminate_auth_and_hostile_wire() -> TestResult {
    let basis = d("basis:del-faults");
    let approval = d("owner-approval:faults");
    let auth = DeletionAuthorityContext::approved(basis, 5, 1, approval);

    // 1. Missing owner approval fails closed BEFORE planning!
    let mut no_approval = auth.clone();
    no_approval.owner_approval_digest = None;
    let empty_cat = ArchiveDeletionCatalog::new();
    let err_auth = DeletionClosureExecutor::plan_closure(
        &empty_cat,
        d("root"),
        &no_approval,
        vec![],
        TimestampNs(100),
        false,
    )
    .expect_err("missing owner approval must fail closed");
    assert!(matches!(
        err_auth,
        DeletionClosureError::AuthorityRevoked(_)
    ));
    assert_eq!(
        err_auth.guidance(),
        DeletionGuidance::ObtainOwnerDeletionApproval
    );

    // 2. Evidence hold + live external shared parent MUST block execution!
    let d_shared_chunk = d("shared-source-chunk");
    let d_held_deriv = d("held-derivative");
    let d_target_root = d("target-manifest");
    let d_other_live_root = d("other-live-manifest");

    let mut held_node = node(
        d_held_deriv,
        DeletionArtifactClass::DerivativeChunk,
        500,
        &[],
    );
    held_node
        .active_holds
        .insert("hold:incident-991".to_owned());

    let mut cat_blocked = ArchiveDeletionCatalog::new();
    cat_blocked.insert(node(
        d_shared_chunk,
        DeletionArtifactClass::SourceChunk,
        1_000,
        &[],
    ));
    cat_blocked.insert(held_node);
    cat_blocked.insert(node(
        d_target_root,
        DeletionArtifactClass::Manifest,
        200,
        &[d_shared_chunk, d_held_deriv],
    ));
    cat_blocked.insert(node(
        d_other_live_root,
        DeletionArtifactClass::Manifest,
        200,
        &[d_shared_chunk],
    ));

    let blocked_plan = DeletionClosureExecutor::plan_closure(
        &cat_blocked,
        d_target_root,
        &auth,
        vec![],
        TimestampNs(200),
        false,
    )?;
    assert!(blocked_plan.is_blocked());
    assert_eq!(blocked_plan.blockers.len(), 2);
    let block_err = DeletionClosureExecutor::execute_and_verify(
        &mut cat_blocked,
        &blocked_plan,
        &auth,
        &BTreeSet::new(),
        TimestampNs(250),
        false,
    )
    .expect_err("blocked plan must refuse execution");
    assert_eq!(
        block_err,
        DeletionClosureError::BlockedByHoldOrSharedReference { blocker_count: 2 }
    );
    assert_eq!(
        block_err.guidance(),
        DeletionGuidance::ResolveHoldsOrSharedParents
    );

    // 3. Adversarial hidden-reference leak corpus: surviving alias detected -> HiddenReferenceLeakDetected!
    let d_leak_chunk = d("leak-chunk");
    let d_leak_alias = d("orphaned-index-hidden-ref");
    let d_leak_root = d("leak-root");
    let mut leak_chunk_node = node(d_leak_chunk, DeletionArtifactClass::SourceChunk, 512, &[]);
    leak_chunk_node.simulate_surviving_hidden_ref = Some(d_leak_alias);
    let mut cat_leak = ArchiveDeletionCatalog::new();
    cat_leak.insert(leak_chunk_node);
    cat_leak.insert(node(
        d_leak_root,
        DeletionArtifactClass::Manifest,
        128,
        &[d_leak_chunk],
    ));
    let leak_plan = DeletionClosureExecutor::plan_closure(
        &cat_leak,
        d_leak_root,
        &auth,
        vec![],
        TimestampNs(300),
        false,
    )?;
    let leak_receipt = DeletionClosureExecutor::execute_and_verify(
        &mut cat_leak,
        &leak_plan,
        &auth,
        &BTreeSet::new(),
        TimestampNs(350),
        false,
    )?;
    assert_eq!(
        leak_receipt.state,
        DeletionClosureState::HiddenReferenceLeakDetected
    );
    assert_eq!(leak_receipt.surviving_hidden_references, vec![d_leak_alias]);

    // 4. Remote provider indeterminate deletion -> `Indeterminate` with NO tombstone root!
    let d_rem = d("remote-s3-replica");
    let d_rem_root = d("remote-manifest");
    let mut cat_indet = ArchiveDeletionCatalog::new();
    cat_indet.insert(node(
        d_rem,
        DeletionArtifactClass::RemoteReplica,
        2_048,
        &[],
    ));
    cat_indet.insert(node(
        d_rem_root,
        DeletionArtifactClass::Manifest,
        128,
        &[d_rem],
    ));
    let indet_plan = DeletionClosureExecutor::plan_closure(
        &cat_indet,
        d_rem_root,
        &auth,
        vec![],
        TimestampNs(400),
        false,
    )?;
    // Cooperative cancellation before apply leaves catalog untouched.
    assert_eq!(
        DeletionClosureExecutor::execute_and_verify(
            &mut cat_indet,
            &indet_plan,
            &auth,
            &BTreeSet::new(),
            TimestampNs(410),
            true,
        ),
        Err(DeletionClosureError::Cancelled)
    );
    // Catalog mutation between plan and apply fails closed as StalePlanOrAuthority!
    let mut cat_drifted = cat_indet.clone();
    cat_drifted.insert(node(
        d("new-object"),
        DeletionArtifactClass::SourceChunk,
        1,
        &[],
    ));
    assert!(matches!(
        DeletionClosureExecutor::execute_and_verify(
            &mut cat_drifted,
            &indet_plan,
            &auth,
            &BTreeSet::new(),
            TimestampNs(420),
            false,
        ),
        Err(DeletionClosureError::StalePlanOrAuthority(_))
    ));
    // Remote deletion timeout/ambiguity -> Indeterminate!
    let indet_targets: BTreeSet<ContentDigest> = [d_rem].into_iter().collect();
    let indet_receipt = DeletionClosureExecutor::execute_and_verify(
        &mut cat_indet,
        &indet_plan,
        &auth,
        &indet_targets,
        TimestampNs(450),
        false,
    )?;
    assert_eq!(indet_receipt.state, DeletionClosureState::Indeterminate);
    assert!(indet_receipt.tombstone_root_digest.is_none());
    assert_eq!(indet_receipt.indeterminate_digests, vec![d_rem]);

    // 5. Hostile wire decoding on `FSSDCL01`.
    let wire = indet_receipt.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        DeletionClosureReceipt::from_canonical_bytes(&bad_magic),
        Err(DeletionClosureError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&88_u32.to_be_bytes());
    assert_eq!(
        DeletionClosureReceipt::from_canonical_bytes(&bad_ver),
        Err(DeletionClosureError::UnsupportedVersion { version: 88 })
    );
    assert!(matches!(
        DeletionClosureReceipt::from_canonical_bytes(&wire[..wire.len() - 5]),
        Err(DeletionClosureError::MalformedWire(_))
    ));
    let mut bit_flip = wire.clone();
    let last = bit_flip.len() - 1;
    bit_flip[last] ^= 0x01;
    assert_eq!(
        DeletionClosureReceipt::from_canonical_bytes(&bit_flip),
        Err(DeletionClosureError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0xFF);
    assert!(matches!(
        DeletionClosureReceipt::from_canonical_bytes(&trailing),
        Err(DeletionClosureError::MalformedWire(_))
    ));

    emit_caplog(
        "fss133_holds_shared_hidden_leaks_indeterminate_and_wire",
        "holds_shared_parents_hidden_ref_leaks_indeterminate_and_wire_verified",
        "holds_shared_parents_hidden_ref_leaks_indeterminate_and_wire_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn partial_apply_preserves_paths_and_reconciles_the_exact_plan_once() -> TestResult {
    let root = d("manifest");
    let index = d("index");
    let local = d("local");
    let remote = d("remote");
    let mut catalog = ArchiveDeletionCatalog::new();
    catalog.insert(node(
        root,
        DeletionArtifactClass::Manifest,
        1,
        &[local, index],
    ));
    catalog.insert(node(
        index,
        DeletionArtifactClass::IndexOrCache,
        2,
        &[remote],
    ));
    catalog.insert(node(local, DeletionArtifactClass::LocalReplica, 4, &[]));
    catalog.insert(node(remote, DeletionArtifactClass::RemoteReplica, 8, &[]));
    let auth = DeletionAuthorityContext::approved(d("basis"), 1, 2, d("approved"));
    let plan = DeletionClosureExecutor::plan_closure(
        &catalog,
        root,
        &auth,
        vec![],
        TimestampNs(1),
        false,
    )?;
    let partial = DeletionClosureExecutor::execute_and_verify(
        &mut catalog,
        &plan,
        &auth,
        &[remote].into(),
        TimestampNs(2),
        false,
    )?;
    assert_eq!(partial.deleted_digests, vec![local]);
    assert_eq!(partial.deleted_bytes, 4);
    assert_eq!(partial.indeterminate_digests, vec![remote]);
    assert!(catalog.get(&root).is_some_and(|n| n.reachable));
    assert!(catalog.tombstone_for(&root).is_none());

    let remaining = DeletionClosureExecutor::plan_closure(
        &catalog,
        root,
        &auth,
        vec![],
        TimestampNs(3),
        false,
    )?;
    assert!(remaining.members.iter().any(|m| m.digest == remote));
    let retry = DeletionClosureExecutor::execute_and_verify(
        &mut catalog,
        &plan,
        &auth,
        &[remote].into(),
        TimestampNs(3),
        false,
    )?;
    assert_eq!(retry, partial);

    let mut changed = catalog.clone();
    let mut held_remote = node(remote, DeletionArtifactClass::RemoteReplica, 8, &[]);
    held_remote.active_holds.insert("hold".into());
    changed.insert(held_remote);
    assert!(matches!(
        DeletionClosureExecutor::execute_and_verify(
            &mut changed,
            &plan,
            &auth,
            &BTreeSet::new(),
            TimestampNs(4),
            false,
        ),
        Err(DeletionClosureError::StalePlanOrAuthority(_))
    ));
    assert!(changed.get(&remote).is_some_and(|n| n.reachable));
    // A late stale report for an already confirmed deletion cannot undo that outcome.
    let receipt = DeletionClosureExecutor::execute_and_verify(
        &mut catalog,
        &plan,
        &auth,
        &[local].into(),
        TimestampNs(5),
        false,
    )?;
    assert_eq!(receipt.state, DeletionClosureState::UnreachabilityVerified);
    assert_eq!(receipt.deleted_digests.len(), 4);
    assert_eq!(receipt.deleted_bytes, 15);
    assert_eq!(receipt.tombstone_root_digest, catalog.tombstone_for(&root));
    assert_eq!(
        receipt,
        DeletionClosureExecutor::execute_and_verify(
            &mut catalog,
            &plan,
            &auth,
            &BTreeSet::new(),
            TimestampNs(6),
            false,
        )?
    );
    let mut revoked = auth;
    revoked.deletion_capability_active = false;
    assert!(matches!(
        DeletionClosureExecutor::execute_and_verify(
            &mut catalog,
            &plan,
            &revoked,
            &BTreeSet::new(),
            TimestampNs(7),
            false,
        ),
        Err(DeletionClosureError::AuthorityRevoked(_))
    ));
    Ok(())
}

#[test]
fn incomplete_membership_and_external_aliases_prevent_deletion() -> TestResult {
    let mut catalog = ArchiveDeletionCatalog::new();
    let root = d("manifest");
    let child = d("child");
    catalog.insert(node(root, DeletionArtifactClass::Manifest, 1, &[child]));
    let auth = DeletionAuthorityContext::approved(d("basis"), 1, 2, d("approved"));
    assert!(matches!(
        DeletionClosureExecutor::plan_closure(&catalog, root, &auth, vec![], TimestampNs(1), false),
        Err(DeletionClosureError::InvalidInput(_))
    ));
    catalog.insert(node(child, DeletionArtifactClass::SourceChunk, 1, &[]));
    let mut other = node(
        d("other-index"),
        DeletionArtifactClass::IndexOrCache,
        1,
        &[],
    );
    other.hidden_reference_aliases.insert(child);
    catalog.insert(other);
    let mut plan = DeletionClosureExecutor::plan_closure(
        &catalog,
        root,
        &auth,
        vec![],
        TimestampNs(2),
        false,
    )?;
    assert_eq!(plan.blockers.len(), 1);
    assert_eq!(plan.blockers[0].target_digest, child);
    assert_eq!(plan.blockers[0].reference_id, d("other-index").to_string());
    // A caller-supplied recomputed checksum cannot remove a witnessed blocker.
    plan.blockers.clear();
    plan.plan_digest = plan.compute_digest()?;
    assert!(matches!(
        DeletionClosureExecutor::execute_and_verify(
            &mut catalog,
            &plan,
            &auth,
            &BTreeSet::new(),
            TimestampNs(3),
            false,
        ),
        Err(DeletionClosureError::StalePlanOrAuthority(_))
    ));
    assert!(catalog.get(&child).is_some_and(|n| n.reachable));
    assert!(catalog.tombstone_for(&root).is_none());
    Ok(())
}

#[test]
fn byte_accounting_refuses_overflow_and_accepts_the_exact_limit() -> TestResult {
    let root = d("manifest");
    let child = d("large-source");
    let auth = DeletionAuthorityContext::approved(d("basis"), 1, 2, d("approved"));
    let mut catalog = ArchiveDeletionCatalog::new();
    catalog.insert(node(root, DeletionArtifactClass::Manifest, 1, &[child]));
    catalog.insert(node(
        child,
        DeletionArtifactClass::SourceChunk,
        u64::MAX,
        &[],
    ));
    assert!(matches!(
        DeletionClosureExecutor::plan_closure(&catalog, root, &auth, vec![], TimestampNs(1), false),
        Err(DeletionClosureError::InvalidInput(_))
    ));
    assert!(catalog.get(&child).is_some_and(|n| n.reachable));
    catalog.insert(node(
        child,
        DeletionArtifactClass::SourceChunk,
        u64::MAX - 1,
        &[],
    ));
    let plan = DeletionClosureExecutor::plan_closure(
        &catalog,
        root,
        &auth,
        vec![],
        TimestampNs(1),
        false,
    )?;
    let receipt = DeletionClosureExecutor::execute_and_verify(
        &mut catalog,
        &plan,
        &auth,
        &BTreeSet::new(),
        TimestampNs(2),
        false,
    )?;
    assert_eq!(plan.total_planned_bytes, u64::MAX);
    assert_eq!(receipt.deleted_bytes, u64::MAX);
    Ok(())
}

#[test]
fn a_closure_whose_terminal_proof_would_exceed_the_wire_limit_remains_intact() -> TestResult {
    use fss_core::DigestAlgorithm;
    use fss_object::deletion_closure::MAX_DELETION_RECEIPT_WIRE_BYTES;
    fn id(n: u32) -> ContentDigest {
        let mut value = [0_u8; 32];
        value[..4].copy_from_slice(&n.to_be_bytes());
        ContentDigest::new(DigestAlgorithm::Sha256, value)
    }

    let root = id(0);
    let mut manifest = node(root, DeletionArtifactClass::Manifest, 1, &[]);
    let mut catalog = ArchiveDeletionCatalog::new();
    // This is a valid one-level closure below the 65,536-member ceiling. Member
    // digests alone fit the v1 wire budget; the distinct surviving aliases do not.
    for n in 1..=63_544 {
        let mut source = node(id(n), DeletionArtifactClass::SourceChunk, 1, &[]);
        source.simulate_surviving_hidden_ref = Some(id(n + 63_544));
        manifest.dependencies.insert(source.digest);
        catalog.insert(source);
    }
    catalog.insert(manifest);
    let auth = DeletionAuthorityContext::approved(d("basis"), 1, 2, d("approved"));
    let mut disclosure = UnknownExternalCopy {
        copy_id: "x".to_owned(),
        destination_label: "y".to_owned(),
        note: "a".repeat(54),
    };
    let plan = DeletionClosureExecutor::plan_closure(
        &catalog,
        root,
        &auth,
        vec![disclosure.clone()],
        TimestampNs(1),
        false,
    )?;
    let before = catalog.catalog_state_digest()?;
    assert!(matches!(
        DeletionClosureExecutor::execute_and_verify(
            &mut catalog,
            &plan,
            &auth,
            &BTreeSet::new(),
            TimestampNs(2),
            false
        ),
        Err(DeletionClosureError::BoundsExceeded {
            maximum: MAX_DELETION_RECEIPT_WIRE_BYTES,
            ..
        })
    ));
    assert_eq!(catalog.catalog_state_digest()?, before);
    assert!(catalog.tombstone_for(&root).is_none());

    // Removing one byte from the disclosure gives a receipt exactly at the v1 ceiling.
    disclosure.note.truncate(53);
    let plan = DeletionClosureExecutor::plan_closure(
        &catalog,
        root,
        &auth,
        vec![disclosure],
        TimestampNs(3),
        false,
    )?;
    let receipt = DeletionClosureExecutor::execute_and_verify(
        &mut catalog,
        &plan,
        &auth,
        &BTreeSet::new(),
        TimestampNs(4),
        false,
    )?;
    let wire = receipt.to_canonical_bytes()?;
    assert_eq!(wire.len(), MAX_DELETION_RECEIPT_WIRE_BYTES);
    assert_eq!(
        DeletionClosureReceipt::from_canonical_bytes(&wire)?,
        receipt
    );
    Ok(())
}
