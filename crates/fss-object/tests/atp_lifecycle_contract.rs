#![forbid(unsafe_code)]
//! Contract and fault tests for canonical ATP transfer, path, and archive lifecycles (`fss-x4a.13.31`).
//!
//! Exercises `crates/fss-object/src/atp_lifecycle/`:
//! - Exhaustive 4-layer crosswalk (`SemanticTransfer`, `ArchivePublication`, `ArchiveObjectCustody`,
//!   `Path`), legacy document spellings, ambiguous bare spelling refusal, and unknown spelling refusal;
//! - Full coupled semantic + archive + multipath lifecycle enforcing root-last publication,
//!   non-collapsible byte/object counters, repair post-digest verification (`XFER-INV-006`),
//!   replica failure-domain diversity, and witnessed proof-of-retrievability before `Complete`;
//! - Cooperative cancellation (`request -> drain -> finalize`) refusing premature path close or
//!   unclassified/unverified-reusable children, plus exact crash-cut replay parity across every
//!   framed journal prefix `0..=N` and fail-closed corruption detection;
//! - Indeterminate terminal reconciliation obligations, quarantine, rejection, authority/privacy
//!   revocation, stale anchors/fences, clock rewind, budgets, and version/critical-extension refusals.

use fss_core::{ContentDigest, TimestampNs};
use fss_object::atp_lifecycle::{
    ATP_LIFECYCLE_FORMAT_VERSION, ArchiveObjectState, ArchivePublicationState,
    AtpLifecycleCoordinator, AtpLifecycleError, AuthoritySnapshot, CanonicalLifecycleState,
    IndeterminateTransferObligation, JournalRecord, LegacyMappingKind, LifecycleEvent,
    LifecycleLayer, NON_COLLAPSE_TERMS, PathState, ProofOfRetrievability, SemanticTransferState,
    StagedChildDisposition, TransferId, TransferJournal, TransferSpec, resolve_state_spelling,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn digest_of(label: &str) -> ContentDigest {
    ContentDigest::sha256(label.as_bytes())
}

fn base_spec(archive_enabled: bool) -> TransferSpec {
    TransferSpec {
        format_version: ATP_LIFECYCLE_FORMAT_VERSION,
        protocol_generation: 1,
        sender: "node:edge-camera-01".to_owned(),
        receiver: "archive:primary-vault".to_owned(),
        session_nonce: 42,
        manifest_root: digest_of("atp-manifest-root-v1"),
        contract_basis_digest: digest_of("contract-basis-v1"),
        transfer_policy_digest: digest_of("transfer-policy-v1"),
        expected_authority_generation: 7,
        initial_fence: 10,
        archive_enabled,
        required_failure_domains: 2,
        expected_children: vec![
            (digest_of("child-a"), 4096),
            (digest_of("child-b"), 2048),
            (digest_of("child-c"), 1024),
        ],
        max_journal_records: 256,
        unknown_critical_extensions: Vec::new(),
    }
}

fn base_authority(spec: &TransferSpec) -> AuthoritySnapshot {
    AuthoritySnapshot {
        contract_basis_digest: spec.contract_basis_digest,
        authority_generation: spec.expected_authority_generation,
        privacy_epoch: 3,
        capability_active: true,
        privacy_active: true,
        destination_authorized: true,
        max_bytes_budget: 1_000_000,
        max_ops_budget: 1_000,
    }
}

#[test]
fn crosswalk_reconciles_all_layers_legacy_spellings_and_refuses_ambiguity_or_unknowns() -> TestResult
{
    assert_eq!(NON_COLLAPSE_TERMS.len(), 11);
    assert_eq!(SemanticTransferState::ALL.len(), 14);
    assert_eq!(ArchivePublicationState::ALL.len(), 18);
    assert_eq!(ArchiveObjectState::ALL.len(), 7);
    assert_eq!(PathState::ALL.len(), 7);

    // Every canonical ID round-trips with its owning layer and refuses mismatched layer hints.
    for s in SemanticTransferState::ALL {
        let res = resolve_state_spelling(s.canonical_id(), Some(LifecycleLayer::SemanticTransfer))?;
        assert_eq!(res.canonical, CanonicalLifecycleState::Semantic(s));
        assert_eq!(res.mapping, LegacyMappingKind::DistinctCanonical);
        assert!(matches!(
            resolve_state_spelling(s.canonical_id(), Some(LifecycleLayer::Path)),
            Err(AtpLifecycleError::LayerMismatch { .. })
        ));
    }
    for a in ArchivePublicationState::ALL {
        let res =
            resolve_state_spelling(a.canonical_id(), Some(LifecycleLayer::ArchivePublication))?;
        assert_eq!(res.canonical, CanonicalLifecycleState::Archive(a));
        assert_eq!(res.mapping, LegacyMappingKind::DistinctCanonical);
    }
    for o in ArchiveObjectState::ALL {
        let res =
            resolve_state_spelling(o.canonical_id(), Some(LifecycleLayer::ArchiveObjectCustody))?;
        assert_eq!(res.canonical, CanonicalLifecycleState::ArchiveObject(o));
    }
    for p in PathState::ALL {
        let res = resolve_state_spelling(p.canonical_id(), Some(LifecycleLayer::Path))?;
        assert_eq!(res.canonical, CanonicalLifecycleState::Path(p));
    }

    // Ambiguous bare spellings shared across semantic and archive layers MUST refuse without hint.
    for ambiguous in [
        "Reserved",
        "Receiving",
        "GraphClosed",
        "Quarantined",
        "Indeterminate",
    ] {
        let err = resolve_state_spelling(ambiguous, None)
            .err()
            .ok_or("expected ambiguous bare spelling refusal")?;
        assert!(matches!(
            err,
            AtpLifecycleError::AmbiguousBareSpelling { .. }
        ));
        assert_eq!(err.refusal_code(), "atp.refuse.unknown_spelling");
        assert!(resolve_state_spelling(ambiguous, Some(LifecycleLayer::SemanticTransfer)).is_ok());
        assert!(
            resolve_state_spelling(ambiguous, Some(LifecycleLayer::ArchivePublication)).is_ok()
        );
    }

    // Legacy cross-document spellings must resolve explicitly without silent discard.
    let legacy_checks: [(&str, CanonicalLifecycleState, LegacyMappingKind); 10] = [
        (
            "ManifestVerified",
            CanonicalLifecycleState::Archive(ArchivePublicationState::ManifestVerified),
            LegacyMappingKind::DistinctCanonical,
        ),
        (
            "ManifestValidated",
            CanonicalLifecycleState::Archive(ArchivePublicationState::ManifestVerified),
            LegacyMappingKind::MappedAlias,
        ),
        (
            "PathsDiscovered",
            CanonicalLifecycleState::Path(PathState::Candidate),
            LegacyMappingKind::LayerRehomed,
        ),
        (
            "ChildrenScheduled",
            CanonicalLifecycleState::Archive(ArchivePublicationState::Fetching),
            LegacyMappingKind::MappedAlias,
        ),
        (
            "ObjectVerified",
            CanonicalLifecycleState::Archive(ArchivePublicationState::ObjectVerified),
            LegacyMappingKind::DistinctCanonical,
        ),
        (
            "GraphClosureVerified",
            CanonicalLifecycleState::Archive(ArchivePublicationState::GraphClosed),
            LegacyMappingKind::MappedAlias,
        ),
        (
            "ExposureReady",
            CanonicalLifecycleState::Archive(ArchivePublicationState::ExposureReady),
            LegacyMappingKind::DistinctCanonical,
        ),
        (
            "RootPublished",
            CanonicalLifecycleState::Archive(ArchivePublicationState::RootPublished),
            LegacyMappingKind::DistinctCanonical,
        ),
        (
            "ReplicaQualified",
            CanonicalLifecycleState::Archive(ArchivePublicationState::ReplicaQualified),
            LegacyMappingKind::DistinctCanonical,
        ),
        (
            "RetrievabilityVerified",
            CanonicalLifecycleState::Archive(ArchivePublicationState::RetrievabilityVerified),
            LegacyMappingKind::DistinctCanonical,
        ),
    ];
    for (spelling, expected_state, expected_kind) in legacy_checks {
        let res = resolve_state_spelling(spelling, None)?;
        assert_eq!(res.canonical, expected_state, "spelling {spelling}");
        assert_eq!(res.mapping, expected_kind, "mapping kind for {spelling}");
    }

    // Ad-hoc / invented transport spellings must fail closed.
    let unknown = resolve_state_spelling("AlmostDone", None)
        .err()
        .ok_or("expected unknown spelling refusal")?;
    assert!(matches!(
        unknown,
        AtpLifecycleError::UnknownStateSpelling { .. }
    ));
    assert_eq!(unknown.refusal_code(), "atp.refuse.unknown_spelling");

    emit_caplog(
        "atp_crosswalk_reconciliation",
        "all_46_canonical_and_10_legacy_resolved",
        "all_46_canonical_and_10_legacy_resolved",
        "pass",
    );
    Ok(())
}

fn assert_custody_refusal(
    coord: &mut AtpLifecycleCoordinator,
    timestamp: TimestampNs,
    event: LifecycleEvent,
) -> TestResult {
    let before = coord.clone();
    let fence = coord.active_fence();
    let live = coord
        .apply_event(fence, timestamp, event.clone(), 0, 1)
        .err()
        .ok_or("accepted an unsupported custody claim")?;
    assert!(
        matches!(live, AtpLifecycleError::InvalidInput(_)),
        "{live:?}"
    );
    assert_eq!(*coord, before);

    // A well-formed, checksummed record with the same claim must fail on cold replay too.
    let mut journal = before.journal().clone();
    journal.append(fence, timestamp, event, 0, 1)?;
    let framed = journal.export_framed_prefix(journal.records().len())?;
    let cold = AtpLifecycleCoordinator::resume_from_framed_bytes(
        before.spec().clone(),
        before.authority().clone(),
        &framed,
    )
    .err()
    .ok_or("replayed an unsupported custody claim")?;
    assert_eq!(live, cold);
    Ok(())
}

#[test]
fn full_semantic_and_archive_lifecycle_enforces_root_last_non_collapse_and_por() -> TestResult {
    let spec = base_spec(true);
    let auth = base_authority(&spec);
    let child_a = spec.expected_children[0].0;
    let child_b = spec.expected_children[1].0;
    let child_c = spec.expected_children[2].0;

    // TransferId is deterministic and sensitive to critical inputs.
    let mut alt_spec = spec.clone();
    alt_spec.session_nonce = 43;
    assert_ne!(spec.transfer_id(), alt_spec.transfer_id());

    let mut coord = AtpLifecycleCoordinator::new(spec.clone(), auth)?;
    assert_eq!(coord.semantic_state(), SemanticTransferState::Proposed);
    assert_eq!(
        coord.archive_state(),
        Some(ArchivePublicationState::Planned)
    );
    assert!(matches!(
        coord.build_receipt(true),
        Err(AtpLifecycleError::ReceiptBeforeCommit { .. })
    ));

    let mut ts = 1000_i128;
    let mut next_ts = || {
        ts += 10;
        TimestampNs(ts)
    };

    // 1. Reserve
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::Reserve {
            reserved_bytes: 16_384,
            reserved_ops: 64,
        },
        0,
        1,
    )?;
    assert_eq!(coord.semantic_state(), SemanticTransferState::Reserved);
    assert_eq!(
        coord.archive_state(),
        Some(ArchivePublicationState::Reserved)
    );

    // Offering graph before ManifestVerified must fail closed in archive mode.
    let err = coord
        .apply_event(
            10,
            next_ts(),
            LifecycleEvent::OfferGraph {
                offered_bytes: 7168,
                offered_objects: 3,
            },
            0,
            1,
        )
        .err()
        .ok_or("expected skipped ManifestVerified refusal")?;
    assert_eq!(err.refusal_code(), "atp.refuse.skipped_publication");

    // Wrong manifest root must fail closed.
    assert!(matches!(
        coord.apply_event(
            10,
            next_ts(),
            LifecycleEvent::VerifyManifest {
                manifest_root: digest_of("wrong-root"),
            },
            0,
            1,
        ),
        Err(AtpLifecycleError::ManifestMismatch { .. })
    ));

    // 2. VerifyManifest -> OfferGraph -> BeginReceiving
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::VerifyManifest {
            manifest_root: spec.manifest_root,
        },
        0,
        1,
    )?;
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::OfferGraph {
            offered_bytes: 7168,
            offered_objects: 3,
        },
        0,
        1,
    )?;
    coord.apply_event(10, next_ts(), LifecycleEvent::BeginReceiving, 0, 1)?;
    assert_eq!(coord.semantic_state(), SemanticTransferState::Receiving);
    assert_eq!(
        coord.archive_state(),
        Some(ArchivePublicationState::Fetching)
    );

    // 3. Multipath lifecycle: Discover -> Candidate -> Probing -> Active (plus Suspect recovery)
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::PathDiscover {
            path_id: "wan-a".to_owned(),
            failure_domain: "fd-rack-a".to_owned(),
        },
        0,
        1,
    )?;
    for to in [PathState::Candidate, PathState::Probing] {
        coord.apply_event(
            10,
            next_ts(),
            LifecycleEvent::PathTransition {
                path_id: "wan-a".to_owned(),
                to,
                reason: "probe".to_owned(),
            },
            0,
            1,
        )?;
    }
    // Delivering over a Probing path must refuse with PathNotActive.
    assert!(matches!(
        coord.apply_event(
            10,
            next_ts(),
            LifecycleEvent::DeliverChild {
                path_id: "wan-a".to_owned(),
                child_digest: child_a,
                bytes: 4096,
                reused_existing: false,
            },
            4096,
            1,
        ),
        Err(AtpLifecycleError::PathNotActive { .. })
    ));
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::PathTransition {
            path_id: "wan-a".to_owned(),
            to: PathState::Active,
            reason: "probe-passed".to_owned(),
        },
        0,
        1,
    )?;
    // Suspect -> Active directly refuses; Suspect -> Probing -> Active succeeds.
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::PathTransition {
            path_id: "wan-a".to_owned(),
            to: PathState::Suspect,
            reason: "jitter".to_owned(),
        },
        0,
        1,
    )?;
    assert!(matches!(
        coord.apply_event(
            10,
            next_ts(),
            LifecycleEvent::PathTransition {
                path_id: "wan-a".to_owned(),
                to: PathState::Active,
                reason: "skip-probe".to_owned(),
            },
            0,
            1,
        ),
        Err(AtpLifecycleError::SkippedTransition { .. })
    ));
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::PathTransition {
            path_id: "wan-a".to_owned(),
            to: PathState::Probing,
            reason: "reprobe".to_owned(),
        },
        0,
        1,
    )?;
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::PathTransition {
            path_id: "wan-a".to_owned(),
            to: PathState::Active,
            reason: "recovered".to_owned(),
        },
        0,
        1,
    )?;

    // 4. Child A delivered fresh (with duplicate delivery idempotency), Child B reused, Child C repaired.
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::DeliverChild {
            path_id: "wan-a".to_owned(),
            child_digest: child_a,
            bytes: 4096,
            reused_existing: false,
        },
        4096,
        1,
    )?;
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::DeliverChild {
            path_id: "wan-a".to_owned(),
            child_digest: child_a,
            bytes: 4096,
            reused_existing: false,
        },
        0,
        1,
    )?;
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::DeliverChild {
            path_id: "wan-a".to_owned(),
            child_digest: child_b,
            bytes: 2048,
            reused_existing: true,
        },
        0,
        1,
    )?;

    // Post-repair digest mismatch MUST refuse (`atp.refuse.repair_digest_mismatch`).
    let repair_err = coord
        .apply_event(
            10,
            next_ts(),
            LifecycleEvent::RepairChild {
                child_digest: child_c,
                reconstructed_digest: digest_of("corrupt-repair"),
                repair_symbols_used: 3,
                bytes: 1024,
            },
            1024,
            1,
        )
        .err()
        .ok_or("expected repair digest mismatch refusal")?;
    assert_eq!(
        repair_err.refusal_code(),
        "atp.refuse.repair_digest_mismatch"
    );

    // Valid repair for child C.
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::RepairChild {
            child_digest: child_c,
            reconstructed_digest: child_c,
            repair_symbols_used: 2,
            bytes: 1024,
        },
        1024,
        1,
    )?;

    // Non-collapsed counters before verification: offered=7168, received=4096, reused=2048, verified=0, committed=0.
    assert_eq!(coord.counters().offered_bytes, 7168);
    assert_eq!(coord.counters().received_bytes, 4096);
    assert_eq!(coord.counters().reused_bytes, 2048);
    assert_eq!(coord.counters().verified_bytes, 0);
    assert_eq!(coord.counters().committed_bytes, 0);
    assert_eq!(coord.counters().duplicate_offers_ignored, 1);
    assert_eq!(coord.counters().repair_symbols_used, 2);

    // MarkStaged now succeeds because all children reached expected_bytes.
    coord.apply_event(10, next_ts(), LifecycleEvent::MarkStaged, 0, 1)?;
    assert_eq!(coord.archive_state(), Some(ArchivePublicationState::Staged));

    // MarkChildrenVerified BEFORE verifying all children must refuse (`atp.refuse.root_before_child`).
    let unverified_err = coord
        .apply_event(10, next_ts(), LifecycleEvent::MarkChildrenVerified, 0, 1)
        .err()
        .ok_or("expected root_before_child when children unverified")?;
    assert_eq!(
        unverified_err.refusal_code(),
        "atp.refuse.root_before_child"
    );

    // Verify all 3 children, and advance child archive custody to RemoteChildrenVerified.
    for (digest, bytes) in spec.expected_children.clone() {
        coord.apply_event(
            10,
            next_ts(),
            LifecycleEvent::VerifyChild {
                child_digest: digest,
                verified_bytes: bytes,
            },
            0,
            1,
        )?;
        for stage in [
            ArchiveObjectState::LocalDurable,
            ArchiveObjectState::RemoteStaged,
            ArchiveObjectState::RemoteChildrenVerified,
        ] {
            coord.apply_event(
                10,
                next_ts(),
                LifecycleEvent::AdvanceChildArchiveState {
                    child_digest: digest,
                    to: stage,
                },
                0,
                1,
            )?;
        }
    }
    assert_eq!(coord.counters().verified_bytes, 7168);
    assert_eq!(coord.counters().verified_objects, 3);
    assert_eq!(coord.counters().committed_bytes, 0);

    // 5. Close the graph and check exposure and durability independently.
    coord.apply_event(10, next_ts(), LifecycleEvent::MarkChildrenVerified, 0, 1)?;
    coord.apply_event(10, next_ts(), LifecycleEvent::CloseGraph, 0, 1)?;

    // Stale privacy_epoch on ExposureReady must refuse.
    assert!(matches!(
        coord.apply_event(
            10,
            next_ts(),
            LifecycleEvent::MarkExposureReady { policy_epoch: 99 },
            0,
            1,
        ),
        Err(AtpLifecycleError::StaleAnchorOrGeneration { .. })
    ));
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::MarkExposureReady { policy_epoch: 3 },
        0,
        1,
    )?;

    let publish = LifecycleEvent::PublishArchiveRoot {
        root_digest: spec.manifest_root,
        provider_tuple: "s3://owner-archive-bucket/site-1/gen-1".to_owned(),
    };
    assert_custody_refusal(&mut coord, next_ts(), publish.clone())?;

    // Insufficient failure domains must refuse.
    assert!(matches!(
        coord.apply_event(
            10,
            next_ts(),
            LifecycleEvent::SatisfyDurability {
                failure_domains: vec!["fd-rack-a".to_owned()],
            },
            0,
            1,
        ),
        Err(AtpLifecycleError::InsufficientFailureDomains {
            required: 2,
            observed: 1,
        })
    ));
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::SatisfyDurability {
            failure_domains: vec!["fd-rack-a".to_owned(), "fd-rack-b".to_owned()],
        },
        0,
        1,
    )?;

    // A provider may publish first, but a sample cannot prove committed reachability yet.
    let mut remote_first = coord.clone();
    remote_first.apply_event(10, next_ts(), publish.clone(), 0, 1)?;
    remote_first.apply_event(
        10,
        next_ts(),
        LifecycleEvent::QualifyReplicas {
            failure_domains: vec!["fd-rack-a".to_owned(), "fd-rack-b".to_owned()],
        },
        0,
        1,
    )?;
    let sampled_at = next_ts();
    let proof = ProofOfRetrievability {
        sample_id: "remote-first".to_owned(),
        root_digest: spec.manifest_root,
        observed_digest: spec.manifest_root,
        sampled_bytes: 7168,
        replica_generation: 1,
        failure_domain: "fd-rack-b".to_owned(),
        sampled_at,
    };
    let verify = |proof| LifecycleEvent::VerifyRetrievability { proof };
    assert_custody_refusal(&mut remote_first, sampled_at, verify(proof.clone()))?;
    let committed_at = next_ts();
    remote_first.apply_event(
        10,
        committed_at,
        LifecycleEvent::CommitRoot {
            root_digest: spec.manifest_root,
            commit_anchor: digest_of("remote-first-ledger-commit"),
        },
        0,
        1,
    )?;
    assert_custody_refusal(&mut remote_first, committed_at, verify(proof.clone()))?;
    let fresh = ProofOfRetrievability {
        sampled_at: committed_at,
        ..proof
    };
    remote_first.apply_event(10, committed_at, verify(fresh), 0, 1)?;
    remote_first.apply_event(10, next_ts(), LifecycleEvent::CompleteArchive, 0, 1)?;

    // 6. Advance fence -> reject stale fence -> CommitRoot -> PublishArchiveRoot
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::AdvanceFence { new_fence: 11 },
        0,
        1,
    )?;
    let stale_err = coord
        .apply_event(
            10,
            next_ts(),
            LifecycleEvent::CommitRoot {
                root_digest: spec.manifest_root,
                commit_anchor: digest_of("ledger-commit-1"),
            },
            0,
            1,
        )
        .err()
        .ok_or("expected stale fence refusal")?;
    assert_eq!(stale_err.refusal_code(), "atp.refuse.stale_fence");

    coord.apply_event(
        11,
        next_ts(),
        LifecycleEvent::CommitRoot {
            root_digest: spec.manifest_root,
            commit_anchor: digest_of("ledger-commit-1"),
        },
        0,
        1,
    )?;
    // Still cannot seal receipt in archive mode until archive root is published!
    assert!(matches!(
        coord.build_receipt(true),
        Err(AtpLifecycleError::ReceiptBeforeCommit { .. })
    ));

    let published_at = next_ts();
    coord.apply_event(11, published_at, publish, 0, 1)?;
    coord.apply_event(
        11,
        next_ts(),
        LifecycleEvent::QualifyReplicas {
            failure_domains: vec!["fd-rack-a".to_owned(), "fd-rack-b".to_owned()],
        },
        0,
        1,
    )?;

    // CompleteArchive BEFORE VerifyRetrievability must fail closed (`atp.refuse.complete_without_retrievability`).
    let por_err = coord
        .apply_event(11, next_ts(), LifecycleEvent::CompleteArchive, 0, 1)
        .err()
        .ok_or("expected refusal without proof-of-retrievability")?;
    assert_eq!(
        por_err.refusal_code(),
        "atp.refuse.complete_without_retrievability"
    );

    let por = ProofOfRetrievability {
        sample_id: "por-sample-001".to_owned(),
        root_digest: spec.manifest_root,
        replica_generation: 1,
        failure_domain: "fd-rack-b".to_owned(),
        observed_digest: spec.manifest_root,
        sampled_bytes: 7168,
        sampled_at: next_ts(),
    };
    let verify_at = next_ts();
    for invalid in [
        ProofOfRetrievability {
            failure_domain: "unqualified-rack".to_owned(),
            ..por.clone()
        },
        ProofOfRetrievability {
            sampled_at: TimestampNs(published_at.0 - 1),
            ..por.clone()
        },
        ProofOfRetrievability {
            sampled_at: TimestampNs(verify_at.0 + 1),
            ..por.clone()
        },
    ] {
        assert_custody_refusal(&mut coord, verify_at, verify(invalid))?;
    }
    coord.apply_event(11, verify_at, verify(por), 0, 1)?;
    coord.apply_event(11, next_ts(), LifecycleEvent::CompleteArchive, 0, 1)?;
    let before_scrub = coord.build_receipt(true)?;
    coord.apply_event(
        11,
        next_ts(),
        LifecycleEvent::ScrubArchive {
            scrub_digest: digest_of("scrub-ok-1"),
        },
        0,
        1,
    )?;
    coord.apply_event(
        11,
        next_ts(),
        LifecycleEvent::RetireArchive {
            deletion_proof: digest_of("graph-complete-delete-1"),
        },
        0,
        1,
    )?;

    // Seal semantic receipt and supersede cleanly.
    assert_custody_refusal(
        &mut coord,
        next_ts(),
        LifecycleEvent::SealReceipt {
            receipt_digest: before_scrub.receipt_digest,
        },
    )?;
    let pre_seal = coord.build_receipt(true)?;
    coord.apply_event(
        11,
        next_ts(),
        LifecycleEvent::SealReceipt {
            receipt_digest: pre_seal.receipt_digest,
        },
        0,
        1,
    )?;
    let sealed = coord.build_receipt(true)?;
    let journal = coord.journal();
    let framed = journal.export_framed_prefix(journal.records().len())?;
    let resumed = AtpLifecycleCoordinator::resume_from_framed_bytes(
        spec.clone(),
        base_authority(&spec),
        &framed,
    )?;
    assert_eq!(resumed.build_receipt(true)?, sealed);
    assert_eq!(sealed.semantic_state, SemanticTransferState::ReceiptSealed);
    assert_eq!(sealed.archive_state, Some(ArchivePublicationState::Retired));
    assert_eq!(sealed.counters.committed_bytes, 7168);
    assert_eq!(sealed.counters.committed_objects, 3);
    assert_eq!(sealed.receipt_digest, sealed.compute_digest());

    let jsonl = sealed.to_jsonl_line(
        "full_semantic_and_archive_lifecycle",
        1331,
        "cargo test -p fss-object --test atp_lifecycle_contract",
    );
    assert!(jsonl.contains("\"schema\":\"fss.transfer_receipt.v1\""));
    assert!(jsonl.contains("\"semanticState\":\"atp.semantic.receipt_sealed\""));
    assert!(jsonl.contains("\"archiveState\":\"atp.archive.retired\""));
    assert!(jsonl.contains("\"publicationFence\":11"));

    // Self-supersession refuses; distinct successor succeeds.
    assert!(matches!(
        coord.apply_event(
            11,
            next_ts(),
            LifecycleEvent::Supersede {
                successor_transfer_id: spec.transfer_id(),
            },
            0,
            1,
        ),
        Err(AtpLifecycleError::InvalidInput(_))
    ));
    let successor = TransferId::from_digest(digest_of("successor-xfer"));
    coord.apply_event(
        11,
        next_ts(),
        LifecycleEvent::Supersede {
            successor_transfer_id: successor,
        },
        0,
        1,
    )?;
    assert_eq!(coord.semantic_state(), SemanticTransferState::Superseded);

    emit_caplog(
        "atp_full_semantic_and_archive_lifecycle",
        "receipt_sealed_and_superseded",
        "receipt_sealed_and_superseded",
        "pass",
    );
    Ok(())
}

#[test]
fn cancellation_drains_multipath_work_classifies_children_and_replays_every_crash_cut() -> TestResult
{
    let spec = base_spec(true);
    let auth = base_authority(&spec);
    let child_a = spec.expected_children[0].0;
    let child_b = spec.expected_children[1].0;
    let child_c = spec.expected_children[2].0;

    let mut coord = AtpLifecycleCoordinator::new(spec.clone(), auth.clone())?;
    let mut ts = 2000_i128;
    let mut next_ts = || {
        ts += 10;
        TimestampNs(ts)
    };

    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::Reserve {
            reserved_bytes: 16_384,
            reserved_ops: 64,
        },
        0,
        1,
    )?;
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::VerifyManifest {
            manifest_root: spec.manifest_root,
        },
        0,
        1,
    )?;
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::OfferGraph {
            offered_bytes: 7168,
            offered_objects: 3,
        },
        0,
        1,
    )?;
    coord.apply_event(10, next_ts(), LifecycleEvent::BeginReceiving, 0, 1)?;
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::PathDiscover {
            path_id: "lan-0".to_owned(),
            failure_domain: "fd-lan".to_owned(),
        },
        0,
        1,
    )?;
    for to in [PathState::Candidate, PathState::Probing, PathState::Active] {
        coord.apply_event(
            10,
            next_ts(),
            LifecycleEvent::PathTransition {
                path_id: "lan-0".to_owned(),
                to,
                reason: "activate".to_owned(),
            },
            0,
            1,
        )?;
    }
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::PathWorkDelta {
            path_id: "lan-0".to_owned(),
            in_flight_ops: 2,
            live_buffers: 3,
            open_handles: 1,
        },
        0,
        1,
    )?;
    // Verify child_a fully, partially deliver child_b, leave child_c untouched.
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::DeliverChild {
            path_id: "lan-0".to_owned(),
            child_digest: child_a,
            bytes: 4096,
            reused_existing: false,
        },
        4096,
        1,
    )?;
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::VerifyChild {
            child_digest: child_a,
            verified_bytes: 4096,
        },
        0,
        1,
    )?;
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::DeliverChild {
            path_id: "lan-0".to_owned(),
            child_digest: child_b,
            bytes: 1024,
            reused_existing: false,
        },
        1024,
        1,
    )?;

    // Request cancellation: forward work and work increases must now be refused.
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::RequestCancel {
            reason: "operator-drain".to_owned(),
        },
        0,
        1,
    )?;
    assert!(coord.is_cancel_requested());
    assert!(matches!(
        coord.apply_event(
            10,
            next_ts(),
            LifecycleEvent::DeliverChild {
                path_id: "lan-0".to_owned(),
                child_digest: child_b,
                bytes: 1024,
                reused_existing: false,
            },
            1024,
            1,
        ),
        Err(AtpLifecycleError::CancellationInProgress)
    ));
    assert!(matches!(
        coord.apply_event(
            10,
            next_ts(),
            LifecycleEvent::PathWorkDelta {
                path_id: "lan-0".to_owned(),
                in_flight_ops: 3,
                live_buffers: 3,
                open_handles: 1,
            },
            0,
            1,
        ),
        Err(AtpLifecycleError::CancellationInProgress)
    ));

    // Move path to Draining; closing with live_work > 0 MUST refuse (`atp.refuse.path_close_live_work`).
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::PathTransition {
            path_id: "lan-0".to_owned(),
            to: PathState::Draining,
            reason: "cancel-drain".to_owned(),
        },
        0,
        1,
    )?;
    let live_err = coord
        .apply_event(
            10,
            next_ts(),
            LifecycleEvent::PathTransition {
                path_id: "lan-0".to_owned(),
                to: PathState::Closed,
                reason: "premature-close".to_owned(),
            },
            0,
            1,
        )
        .err()
        .ok_or("expected path_close_live_work refusal")?;
    assert_eq!(live_err.refusal_code(), "atp.refuse.path_close_live_work");

    // FinalizeCancel while path is still Draining must refuse with ActivePathsRemaining.
    assert!(matches!(
        coord.apply_event(
            10,
            next_ts(),
            LifecycleEvent::FinalizeCancel {
                child_dispositions: vec![
                    (child_a, StagedChildDisposition::Reusable),
                    (child_b, StagedChildDisposition::Collectable),
                    (child_c, StagedChildDisposition::Collectable),
                ],
            },
            0,
            1,
        ),
        Err(AtpLifecycleError::ActivePathsRemaining { .. })
    ));

    // Drain live work to zero and close path cleanly.
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::PathWorkDelta {
            path_id: "lan-0".to_owned(),
            in_flight_ops: 0,
            live_buffers: 0,
            open_handles: 0,
        },
        0,
        1,
    )?;
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::PathTransition {
            path_id: "lan-0".to_owned(),
            to: PathState::Closed,
            reason: "drained".to_owned(),
        },
        0,
        1,
    )?;

    // Marking unverified child_b Reusable must fail closed.
    assert!(matches!(
        coord.apply_event(
            10,
            next_ts(),
            LifecycleEvent::FinalizeCancel {
                child_dispositions: vec![
                    (child_a, StagedChildDisposition::Reusable),
                    (child_b, StagedChildDisposition::Reusable),
                    (child_c, StagedChildDisposition::Collectable),
                ],
            },
            0,
            1,
        ),
        Err(AtpLifecycleError::InvalidInput(_))
    ));

    // Finalize cancellation with valid child dispositions.
    coord.apply_event(
        10,
        next_ts(),
        LifecycleEvent::FinalizeCancel {
            child_dispositions: vec![
                (child_a, StagedChildDisposition::Reusable),
                (child_b, StagedChildDisposition::Collectable),
                (child_c, StagedChildDisposition::Collectable),
            ],
        },
        0,
        1,
    )?;
    assert_eq!(coord.semantic_state(), SemanticTransferState::Aborted);
    assert_eq!(
        coord.archive_state(),
        Some(ArchivePublicationState::Cancelled)
    );

    // Crash-cut replay parity across EVERY framed journal prefix 0..=total_records.
    let total = coord.journal().records().len();
    assert!(total >= 15);
    for cut in 0..=total {
        let framed = coord.journal().export_framed_prefix(cut)?;
        let replayed =
            AtpLifecycleCoordinator::resume_from_framed_bytes(spec.clone(), auth.clone(), &framed)?;
        assert_eq!(replayed.journal().records().len(), cut);
        if cut == total {
            assert_eq!(replayed, coord);
            assert_eq!(
                replayed.build_receipt(false)?.receipt_digest,
                coord.build_receipt(false)?.receipt_digest
            );
        }
    }

    // Torn frame, flipped checksum byte, and wrong transfer_id must all fail closed.
    let full_framed = coord.journal().export_framed_prefix(total)?;
    let torn = &full_framed[..full_framed.len() - 3];
    assert!(matches!(
        AtpLifecycleCoordinator::resume_from_framed_bytes(spec.clone(), auth.clone(), torn),
        Err(AtpLifecycleError::JournalCorrupt { .. })
    ));
    let mut flipped = full_framed.clone();
    let mid = flipped.len() / 2;
    flipped[mid] ^= 0xFF;
    assert!(matches!(
        AtpLifecycleCoordinator::resume_from_framed_bytes(spec.clone(), auth.clone(), &flipped),
        Err(AtpLifecycleError::JournalCorrupt { .. }
            | AtpLifecycleError::IncompatibleVersion { .. })
    ));
    let mut other_spec = spec.clone();
    other_spec.session_nonce = 9999;
    assert!(matches!(
        TransferJournal::decode_framed_records(other_spec.transfer_id(), &full_framed, 256),
        Err(AtpLifecycleError::JournalCorrupt { .. })
    ));

    // Sequence gap and broken prev_digest fail replay.
    let mut bad_records: Vec<JournalRecord> = coord.journal().records().to_vec();
    if bad_records.len() >= 3 {
        bad_records.remove(1);
        assert!(matches!(
            AtpLifecycleCoordinator::replay(spec, auth, &bad_records),
            Err(AtpLifecycleError::JournalCorrupt { .. })
        ));
    }

    emit_caplog(
        "atp_cancel_drain_and_crash_replay",
        "all_crash_cuts_bit_identical",
        "all_crash_cuts_bit_identical",
        "pass",
    );
    Ok(())
}

#[test]
fn indeterminate_quarantine_revocation_bounds_and_version_refusals() -> TestResult {
    // 1. Version & critical extension refusals at admission.
    let mut bad_ver = base_spec(false);
    bad_ver.format_version = 99;
    assert_eq!(
        AtpLifecycleCoordinator::new(bad_ver.clone(), base_authority(&bad_ver))
            .err()
            .ok_or("expected bad format_version refusal")?
            .refusal_code(),
        "atp.refuse.incompatible_version"
    );
    let mut bad_ext = base_spec(false);
    bad_ext
        .unknown_critical_extensions
        .push("crit.quantum-wormhole.v9".to_owned());
    assert_eq!(
        AtpLifecycleCoordinator::new(bad_ext.clone(), base_authority(&bad_ext))
            .err()
            .ok_or("expected unknown critical extension refusal")?
            .refusal_code(),
        "atp.refuse.incompatible_version"
    );

    // 2. Indeterminate terminal state carries a durable reconciliation obligation.
    let spec = base_spec(true);
    let auth = base_authority(&spec);
    let mut ind = AtpLifecycleCoordinator::new(spec.clone(), auth)?;
    ind.apply_event(
        10,
        TimestampNs(100),
        LifecycleEvent::Reserve {
            reserved_bytes: 8192,
            reserved_ops: 32,
        },
        0,
        1,
    )?;
    ind.apply_event(
        10,
        TimestampNs(110),
        LifecycleEvent::VerifyManifest {
            manifest_root: spec.manifest_root,
        },
        0,
        1,
    )?;
    ind.apply_event(
        10,
        TimestampNs(120),
        LifecycleEvent::OfferGraph {
            offered_bytes: 7168,
            offered_objects: 3,
        },
        0,
        1,
    )?;
    ind.apply_event(10, TimestampNs(130), LifecycleEvent::BeginReceiving, 0, 1)?;
    // Clock rewind refused.
    assert!(matches!(
        ind.apply_event(
            10,
            TimestampNs(125),
            LifecycleEvent::RequestCancel {
                reason: "late".to_owned(),
            },
            0,
            1,
        ),
        Err(AtpLifecycleError::ClockRewind { .. })
    ));
    let early_obligation = IndeterminateTransferObligation {
        obligation_id: "obl:too-early".to_owned(),
        transfer_id: spec.transfer_id(),
        fence: 10,
        reason: "cannot_be_indeterminate_while_fetching".to_owned(),
        follow_up_digest: digest_of("reconcile-early"),
        created_at: TimestampNs(135),
    };
    // Premature Indeterminate during Fetching (before commit/publication boundary) refuses.
    assert!(matches!(
        ind.apply_event(
            10,
            TimestampNs(135),
            LifecycleEvent::MarkIndeterminate {
                obligation: early_obligation,
                archive_state_affected: true,
            },
            0,
            1,
        ),
        Err(AtpLifecycleError::SkippedTransition { .. })
    ));
    // Advance cleanly to DurabilitySatisfied / ExposureReady (the remote publication boundary).
    ind.apply_event(
        10,
        TimestampNs(140),
        LifecycleEvent::PathDiscover {
            path_id: "p0".to_owned(),
            failure_domain: "fd-a".to_owned(),
        },
        0,
        1,
    )?;
    for (idx, to) in [PathState::Candidate, PathState::Probing, PathState::Active]
        .into_iter()
        .enumerate()
    {
        ind.apply_event(
            10,
            TimestampNs(150 + idx as i128 * 10),
            LifecycleEvent::PathTransition {
                path_id: "p0".to_owned(),
                to,
                reason: "ready".to_owned(),
            },
            0,
            1,
        )?;
    }
    let mut t = 180_i128;
    for (digest, bytes) in spec.expected_children.clone() {
        t += 10;
        ind.apply_event(
            10,
            TimestampNs(t),
            LifecycleEvent::DeliverChild {
                path_id: "p0".to_owned(),
                child_digest: digest,
                bytes,
                reused_existing: false,
            },
            bytes,
            1,
        )?;
        t += 10;
        ind.apply_event(
            10,
            TimestampNs(t),
            LifecycleEvent::VerifyChild {
                child_digest: digest,
                verified_bytes: bytes,
            },
            0,
            1,
        )?;
    }
    ind.apply_event(10, TimestampNs(t + 10), LifecycleEvent::MarkStaged, 0, 1)?;
    ind.apply_event(
        10,
        TimestampNs(t + 20),
        LifecycleEvent::MarkChildrenVerified,
        0,
        1,
    )?;
    ind.apply_event(10, TimestampNs(t + 30), LifecycleEvent::CloseGraph, 0, 1)?;
    ind.apply_event(
        10,
        TimestampNs(t + 40),
        LifecycleEvent::SatisfyDurability {
            failure_domains: vec!["fd-a".to_owned(), "fd-b".to_owned()],
        },
        0,
        1,
    )?;
    ind.apply_event(
        10,
        TimestampNs(t + 50),
        LifecycleEvent::MarkExposureReady { policy_epoch: 3 },
        0,
        1,
    )?;
    let obligation = IndeterminateTransferObligation {
        obligation_id: "obl:reconcile-commit-42".to_owned(),
        transfer_id: spec.transfer_id(),
        fence: 10,
        reason: "remote_commit_ack_lost_lookup_timeout".to_owned(),
        follow_up_digest: digest_of("reconcile-handle-42"),
        created_at: TimestampNs(t + 60),
    };
    ind.apply_event(
        10,
        TimestampNs(t + 60),
        LifecycleEvent::MarkIndeterminate {
            obligation: obligation.clone(),
            archive_state_affected: true,
        },
        0,
        1,
    )?;
    assert_eq!(ind.semantic_state(), SemanticTransferState::Indeterminate);
    assert_eq!(
        ind.archive_state(),
        Some(ArchivePublicationState::Indeterminate)
    );
    assert_eq!(ind.reconciliation_obligation(), Some(&obligation));
    let ind_receipt = ind.build_receipt(false)?;
    assert!(
        ind_receipt
            .to_jsonl_line("indeterminate", 1, "repro")
            .contains("\"obligationId\":\"obl:reconcile-commit-42\"")
    );

    // 3. Mid-transfer authority revocation blocks forward progress but permits Quarantine/Cancel;
    //    Quarantine in Reserved (before Offer) must fail closed with SkippedTransition.
    let spec2 = base_spec(false);
    let mut auth2 = base_authority(&spec2);
    auth2.max_ops_budget = 10;
    let mut rev = AtpLifecycleCoordinator::new(spec2.clone(), auth2.clone())?;
    rev.apply_event(
        10,
        TimestampNs(10),
        LifecycleEvent::Reserve {
            reserved_bytes: 8192,
            reserved_ops: 4,
        },
        0,
        1,
    )?;
    let child_a = spec2.expected_children[0].0;
    assert!(matches!(
        rev.apply_event(
            10,
            TimestampNs(15),
            LifecycleEvent::Quarantine {
                reason: "too-early".to_owned(),
                affected_children: vec![child_a],
            },
            0,
            1,
        ),
        Err(AtpLifecycleError::SkippedTransition { .. })
    ));
    rev.apply_event(
        10,
        TimestampNs(20),
        LifecycleEvent::OfferGraph {
            offered_bytes: 7168,
            offered_objects: 3,
        },
        0,
        1,
    )?;
    auth2.capability_active = false;
    rev.update_authority(auth2);
    let rev_err = rev
        .apply_event(10, TimestampNs(30), LifecycleEvent::BeginReceiving, 0, 1)
        .err()
        .ok_or("expected authority revocation refusal")?;
    assert_eq!(rev_err.refusal_code(), "atp.refuse.authority_revoked");
    // Undeclared child in Quarantine must refuse; valid child quarantines cleanly even after revocation.
    assert!(matches!(
        rev.apply_event(
            10,
            TimestampNs(35),
            LifecycleEvent::Quarantine {
                reason: "bad-child".to_owned(),
                affected_children: vec![digest_of("undeclared")],
            },
            0,
            1,
        ),
        Err(AtpLifecycleError::UndeclaredChild { .. })
    ));
    rev.apply_event(
        10,
        TimestampNs(40),
        LifecycleEvent::Quarantine {
            reason: "corrupt-staged-bytes".to_owned(),
            affected_children: vec![child_a],
        },
        0,
        1,
    )?;
    assert_eq!(rev.semantic_state(), SemanticTransferState::Quarantined);
    assert_eq!(
        rev.children()[&child_a].disposition,
        StagedChildDisposition::Quarantined
    );

    // 4. Reject from Proposed and BudgetExhausted check.
    let spec3 = base_spec(false);
    let mut auth3 = base_authority(&spec3);
    auth3.max_bytes_budget = 100;
    let mut rej = AtpLifecycleCoordinator::new(spec3, auth3)?;
    assert!(matches!(
        rej.apply_event(
            10,
            TimestampNs(10),
            LifecycleEvent::Reserve {
                reserved_bytes: 200,
                reserved_ops: 1,
            },
            0,
            1,
        ),
        Err(AtpLifecycleError::BudgetExhausted { .. })
    ));
    rej.apply_event(
        10,
        TimestampNs(20),
        LifecycleEvent::Reject {
            reason: "policy-denied".to_owned(),
        },
        0,
        1,
    )?;
    assert_eq!(rej.semantic_state(), SemanticTransferState::Rejected);

    emit_caplog(
        "atp_faults_indeterminate_quarantine_revocation",
        "all_fault_classes_enforced",
        "all_fault_classes_enforced",
        "pass",
    );
    Ok(())
}
