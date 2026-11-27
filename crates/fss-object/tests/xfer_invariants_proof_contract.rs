#![forbid(unsafe_code)]
//! Normative ATP object-graph transfer invariant proof suite covering ALL TEN invariants:
//! - `XFER-INV-001` (`fss-x4a.13.21`): immutable roots only (no mutable state/creds/effect authority).
//! - `XFER-INV-002` (`fss-x4a.13.22`): deterministic transfer identity sensitive to every critical input.
//! - `XFER-INV-003` (`fss-x4a.13.23`): offered, verified, and committed are strictly distinct.
//! - `XFER-INV-004` (`fss-x4a.13.24`): root last (no visible root over missing/unverified children).
//! - `XFER-INV-005` (`fss-x4a.13.25`): path delivery is not semantic completion.
//! - `XFER-INV-006` (`fss-x4a.13.26`): repair reconstructs bytes only and cannot invent authority.
//! - `XFER-INV-007` (`fss-x4a.13.27`): adaptive multipath transport fails closed to safe policy bounds.
//! - `XFER-INV-008` (`fss-x4a.13.28`): cancellation stops offers, drains paths, classifies staged children.
//! - `XFER-INV-009` (`fss-x4a.13.29`): retention and deletion are explicit canonical-graph effects.
//! - `XFER-INV-010` (`fss-x4a.13.30`): transfer receipts and journals are canonical tamper-evident facts.

use std::collections::BTreeSet;
use std::error::Error;

use fss_core::{ContentDigest, TimestampNs};
use fss_object::ObjectManifest;
use fss_object::atp_lifecycle::{
    ATP_LIFECYCLE_FORMAT_VERSION, ArchivePublicationState, AtpLifecycleCoordinator,
    AtpLifecycleError, AuthoritySnapshot, LifecycleEvent, LifecycleLayer, NON_COLLAPSE_TERMS,
    PathState, SemanticTransferState, StagedChildDisposition, TransferId, TransferSpec,
    resolve_state_spelling,
};
use fss_object::closure::CustodyLevel;
use fss_object::deletion_closure::{
    ArchiveDeletionCatalog, DeletionArtifactClass, DeletionAuthorityContext, DeletionClosureError,
    DeletionClosureExecutor, DeletionGraphNode,
};
use fss_object::multipath::{
    MultipathCandidate, MultipathRaceCoordinator, MultipathRaceState, PathKind, PathPolicyClamp,
    RaceAuthorityContext,
};
use fss_object::repair_gate::{
    PostRepairDigestGate, RepairAuthorityContext, RepairGateState, RepairLease, RepairPlan,
};

type TestResult = Result<(), Box<dyn Error>>;

fn d(label: &str) -> ContentDigest {
    ContentDigest::sha256(label.as_bytes())
}

fn emit_xfer_caplog(invariant: &str, detail: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"invariant\":\"{invariant}\",\"detail\":\"{detail}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn base_spec(archive_enabled: bool) -> TransferSpec {
    TransferSpec {
        format_version: ATP_LIFECYCLE_FORMAT_VERSION,
        protocol_generation: 1,
        sender: "node:cam-edge-01".to_owned(),
        receiver: "archive:vault-01".to_owned(),
        session_nonce: 77,
        manifest_root: d("xfer-manifest-root"),
        contract_basis_digest: d("xfer-basis-v1"),
        transfer_policy_digest: d("xfer-policy-v1"),
        expected_authority_generation: 5,
        initial_fence: 10,
        archive_enabled,
        required_failure_domains: 2,
        expected_children: vec![(d("child-0"), 2_048), (d("child-1"), 1_024)],
        max_journal_records: 256,
        unknown_critical_extensions: Vec::new(),
    }
}

fn base_auth(spec: &TransferSpec) -> AuthoritySnapshot {
    AuthoritySnapshot {
        contract_basis_digest: spec.contract_basis_digest,
        authority_generation: spec.expected_authority_generation,
        privacy_epoch: 2,
        capability_active: true,
        privacy_active: true,
        destination_authorized: true,
        max_bytes_budget: 1_000_000,
        max_ops_budget: 1_000,
    }
}

#[test]
fn xfer_inv_001_and_002_immutable_roots_and_deterministic_transfer_identity() -> TestResult {
    // XFER-INV-001: immutable content-addressed ObjectManifest + refusal of unknown critical extensions
    // and smuggled effect authority in repair & multipath contexts.
    let c0 = d("chunk-0");
    let c1 = d("chunk-1");
    let m1 = ObjectManifest::new("incident_transfer", [c0, c1], None)?;
    let m2 = ObjectManifest::new("incident_transfer", [c1, c0], None)?;
    assert_eq!(m1.root(), m2.root());

    let mut bad_ext_spec = base_spec(false);
    bad_ext_spec.unknown_critical_extensions = vec!["ambient_effect_token".to_owned()];
    assert!(AtpLifecycleCoordinator::new(bad_ext_spec.clone(), base_auth(&bad_ext_spec)).is_err());

    let mut bad_race_auth = RaceAuthorityContext::active(d("basis"), 1, 1);
    bad_race_auth.grants_effect_authority = true;
    assert!(
        MultipathRaceCoordinator::plan(
            base_spec(false).transfer_id(),
            c0,
            64,
            PathPolicyClamp {
                allowed_residency_zones: BTreeSet::from(["local".to_owned()]),
                allowed_kinds: BTreeSet::from([PathKind::LanPeer]),
                max_egress_cost_micros: 1_000,
                max_latency_ms: 100,
                max_concurrent_hedges: 1,
                require_privacy_authorized: true,
                require_integrity_verified: true,
            },
            &bad_race_auth,
            vec![MultipathCandidate {
                path_id: "lan-1".to_owned(),
                kind: PathKind::LanPeer,
                failure_domain: "dom-a".to_owned(),
                residency_zone: "local".to_owned(),
                privacy_authorized: true,
                integrity_verified: true,
                estimated_latency_ms: 5,
                estimated_egress_cost_micros: 0,
            }],
            TimestampNs(100),
            false,
        )
        .is_err()
    );
    emit_xfer_caplog(
        "XFER-INV-001",
        "immutable_roots_and_zero_effect_authority_enforced",
        "ok",
    );

    // XFER-INV-002: deterministic TransferId identical on retry and sensitive to ALL 7 inputs!
    let base_id = TransferId::derive(
        1,
        "sender-a",
        "recv-b",
        99,
        m1.root(),
        d("basis-1"),
        d("policy-1"),
    );
    assert_eq!(
        base_id,
        TransferId::derive(
            1,
            "sender-a",
            "recv-b",
            99,
            m1.root(),
            d("basis-1"),
            d("policy-1"),
        )
    );
    let variants = [
        TransferId::derive(
            2,
            "sender-a",
            "recv-b",
            99,
            m1.root(),
            d("basis-1"),
            d("policy-1"),
        ),
        TransferId::derive(
            1,
            "sender-other",
            "recv-b",
            99,
            m1.root(),
            d("basis-1"),
            d("policy-1"),
        ),
        TransferId::derive(
            1,
            "sender-a",
            "recv-other",
            99,
            m1.root(),
            d("basis-1"),
            d("policy-1"),
        ),
        TransferId::derive(
            1,
            "sender-a",
            "recv-b",
            100,
            m1.root(),
            d("basis-1"),
            d("policy-1"),
        ),
        TransferId::derive(
            1,
            "sender-a",
            "recv-b",
            99,
            d("other-root"),
            d("basis-1"),
            d("policy-1"),
        ),
        TransferId::derive(
            1,
            "sender-a",
            "recv-b",
            99,
            m1.root(),
            d("basis-2"),
            d("policy-1"),
        ),
        TransferId::derive(
            1,
            "sender-a",
            "recv-b",
            99,
            m1.root(),
            d("basis-1"),
            d("policy-2"),
        ),
    ];
    for alt in variants {
        assert_ne!(base_id, alt);
    }
    emit_xfer_caplog("XFER-INV-002", "all_7_critical_inputs_distinct", "ok");
    Ok(())
}

#[test]
fn xfer_inv_003_004_005_008_and_010_non_collapse_root_last_cancel_and_journal_replay() -> TestResult
{
    assert_eq!(NON_COLLAPSE_TERMS.len(), 11);
    assert!(
        resolve_state_spelling("atp.path.active", Some(LifecycleLayer::SemanticTransfer)).is_err()
    );

    let spec = base_spec(true);
    let auth = base_auth(&spec);
    let child_0 = spec.expected_children[0].0;
    let child_1 = spec.expected_children[1].0;
    let mut coord = AtpLifecycleCoordinator::new(spec.clone(), auth.clone())?;

    let mut ts = 1_000_i128;
    let mut tick = || {
        ts += 10;
        TimestampNs(ts)
    };

    coord.apply_event(
        10,
        tick(),
        LifecycleEvent::Reserve {
            reserved_bytes: 8_192,
            reserved_ops: 32,
        },
        0,
        1,
    )?;
    coord.apply_event(
        10,
        tick(),
        LifecycleEvent::VerifyManifest {
            manifest_root: spec.manifest_root,
        },
        0,
        1,
    )?;
    coord.apply_event(
        10,
        tick(),
        LifecycleEvent::OfferGraph {
            offered_bytes: 3_072,
            offered_objects: 2,
        },
        0,
        1,
    )?;
    coord.apply_event(10, tick(), LifecycleEvent::BeginReceiving, 0, 1)?;
    coord.apply_event(
        10,
        tick(),
        LifecycleEvent::PathDiscover {
            path_id: "lan-0".to_owned(),
            failure_domain: "fd-a".to_owned(),
        },
        0,
        1,
    )?;
    for to in [PathState::Candidate, PathState::Probing, PathState::Active] {
        coord.apply_event(
            10,
            tick(),
            LifecycleEvent::PathTransition {
                path_id: "lan-0".to_owned(),
                to,
                reason: "bringup".to_owned(),
            },
            0,
            1,
        )?;
    }

    // Deliver BOTH children over active transport path (path ACK/delivery complete!).
    coord.apply_event(
        10,
        tick(),
        LifecycleEvent::DeliverChild {
            path_id: "lan-0".to_owned(),
            child_digest: child_0,
            bytes: 2_048,
            reused_existing: false,
        },
        2_048,
        1,
    )?;
    coord.apply_event(
        10,
        tick(),
        LifecycleEvent::DeliverChild {
            path_id: "lan-0".to_owned(),
            child_digest: child_1,
            bytes: 1_024,
            reused_existing: false,
        },
        1_024,
        1,
    )?;

    // XFER-INV-003: offered (3072) & received (3072) != verified (0) != committed (0)!
    assert_eq!(coord.counters().offered_bytes, 3_072);
    assert_eq!(coord.counters().received_bytes, 3_072);
    assert_eq!(coord.counters().verified_bytes, 0);
    assert_eq!(coord.counters().committed_bytes, 0);
    emit_xfer_caplog(
        "XFER-INV-003",
        "offered_received_verified_committed_distinct",
        "ok",
    );

    // XFER-INV-005: full path delivery does NOT advance to Committed or Complete!
    assert_eq!(coord.semantic_state(), SemanticTransferState::Receiving);
    assert_eq!(
        coord.archive_state(),
        Some(ArchivePublicationState::Fetching)
    );
    assert!(matches!(
        coord.build_receipt(true),
        Err(AtpLifecycleError::ReceiptBeforeCommit { .. })
    ));
    emit_xfer_caplog(
        "XFER-INV-005",
        "path_delivery_is_not_semantic_completion",
        "ok",
    );

    // XFER-INV-004: Root-last — MarkChildrenVerified MUST refuse while child_1 is unverified!
    coord.apply_event(10, tick(), LifecycleEvent::MarkStaged, 0, 1)?;
    coord.apply_event(
        10,
        tick(),
        LifecycleEvent::VerifyChild {
            child_digest: child_0,
            verified_bytes: 2_048,
        },
        0,
        1,
    )?;
    let root_err = coord
        .apply_event(10, tick(), LifecycleEvent::MarkChildrenVerified, 0, 1)
        .err()
        .ok_or("expected root_before_child refusal")?;
    assert_eq!(root_err.refusal_code(), "atp.refuse.root_before_child");
    emit_xfer_caplog("XFER-INV-004", "root_before_child_refused", "ok");

    // XFER-INV-008: Cancellation stops offers, drains path, classifies staged children!
    coord.apply_event(
        10,
        tick(),
        LifecycleEvent::RequestCancel {
            reason: "owner-cancel".to_owned(),
        },
        0,
        1,
    )?;
    assert!(matches!(
        coord.apply_event(
            10,
            tick(),
            LifecycleEvent::DeliverChild {
                path_id: "lan-0".to_owned(),
                child_digest: child_1,
                bytes: 1_024,
                reused_existing: false,
            },
            0,
            1,
        ),
        Err(AtpLifecycleError::CancellationInProgress)
    ));
    coord.apply_event(
        10,
        tick(),
        LifecycleEvent::PathTransition {
            path_id: "lan-0".to_owned(),
            to: PathState::Draining,
            reason: "drain".to_owned(),
        },
        0,
        1,
    )?;
    coord.apply_event(
        10,
        tick(),
        LifecycleEvent::PathTransition {
            path_id: "lan-0".to_owned(),
            to: PathState::Closed,
            reason: "drained".to_owned(),
        },
        0,
        1,
    )?;
    // Unverified child_1 CANNOT be classified as Reusable!
    assert!(
        coord
            .apply_event(
                10,
                tick(),
                LifecycleEvent::FinalizeCancel {
                    child_dispositions: vec![
                        (child_0, StagedChildDisposition::Reusable),
                        (child_1, StagedChildDisposition::Reusable),
                    ],
                },
                0,
                1,
            )
            .is_err()
    );
    coord.apply_event(
        10,
        tick(),
        LifecycleEvent::FinalizeCancel {
            child_dispositions: vec![
                (child_0, StagedChildDisposition::Reusable),
                (child_1, StagedChildDisposition::Collectable),
            ],
        },
        0,
        1,
    )?;
    assert_eq!(coord.semantic_state(), SemanticTransferState::Aborted);
    emit_xfer_caplog(
        "XFER-INV-008",
        "cancel_drained_and_children_classified",
        "ok",
    );

    // XFER-INV-010: Canonical framed TransferJournal replays bit-identically & rejects corruption!
    let framed = coord
        .journal()
        .export_framed_prefix(coord.journal().records().len())?;
    let replayed =
        AtpLifecycleCoordinator::resume_from_framed_bytes(spec.clone(), auth.clone(), &framed)?;
    assert_eq!(replayed, coord);

    let mut corrupted = framed;
    if let Some(last) = corrupted.last_mut() {
        *last ^= 0xFF;
    }
    assert!(AtpLifecycleCoordinator::resume_from_framed_bytes(spec, auth, &corrupted).is_err());
    emit_xfer_caplog(
        "XFER-INV-010",
        "journal_replay_exact_and_tamper_refused",
        "ok",
    );
    Ok(())
}

#[test]
fn xfer_inv_006_007_and_009_repair_authority_adaptive_fail_closed_and_deletion_closure()
-> TestResult {
    // XFER-INV-006: GF(256) repair reconstructs bytes for known digest & refuses stale/smuggled authority!
    let payload: Vec<u8> = (0..512_usize)
        .map(|i| ((i * 31 + 7) & 0xFF) as u8)
        .collect();
    let target = ContentDigest::sha256(&payload);
    let basis = d("repair-basis");
    let plan = RepairPlan::seal(d("repair-root"), target, 512, 1, basis, 4, 64, 3)?;
    let symbols = plan.encode_symbols(&payload)?;
    let surviving: Vec<_> = symbols.into_iter().skip(3).collect(); // lost first 3 source symbols!

    let good_auth = RepairAuthorityContext::active(basis, 4, 1);
    let lease = RepairLease {
        lease_id: "lease-1".to_owned(),
        plan_digest: plan.plan_digest,
        fence: 1,
        authority_generation: 4,
        expires_at: TimestampNs(10_000),
        active: true,
    };
    let ok_repair = PostRepairDigestGate::reconstruct_and_verify(
        &plan,
        &good_auth,
        &lease,
        1,
        &surviving,
        TimestampNs(1_000),
        false,
        false,
    )?;
    assert_eq!(
        ok_repair.receipt.state,
        RepairGateState::VerifiedCanonicalMatch
    );
    assert_eq!(
        ok_repair.verified_bytes.as_deref(),
        Some(payload.as_slice())
    );

    let mut smuggled_auth = good_auth;
    smuggled_auth.grants_effect_authority = true;
    assert!(
        PostRepairDigestGate::reconstruct_and_verify(
            &plan,
            &smuggled_auth,
            &lease,
            1,
            &surviving,
            TimestampNs(1_000),
            false,
            false,
        )
        .is_err()
    );
    emit_xfer_caplog(
        "XFER-INV-006",
        "repair_verified_and_authority_escalation_refused",
        "ok",
    );

    // XFER-INV-007: Adaptive multipath transport hard-clamps unauthorized/over-cost paths to safe baseline!
    let policy = PathPolicyClamp {
        allowed_residency_zones: BTreeSet::from(["local".to_owned()]),
        allowed_kinds: BTreeSet::from([PathKind::LanPeer, PathKind::CloudProvider]),
        max_egress_cost_micros: 1_000,
        max_latency_ms: 200,
        max_concurrent_hedges: 1,
        require_privacy_authorized: true,
        require_integrity_verified: true,
    };
    let race_auth = RaceAuthorityContext::active(basis, 4, 1);
    let mut race = MultipathRaceCoordinator::plan(
        base_spec(false).transfer_id(),
        target,
        512,
        policy,
        &race_auth,
        vec![
            MultipathCandidate {
                path_id: "fast-unverified".to_owned(),
                kind: PathKind::LanPeer,
                failure_domain: "dom-bad".to_owned(),
                residency_zone: "local".to_owned(),
                privacy_authorized: true,
                integrity_verified: false, // MUST be clamped!
                estimated_latency_ms: 1,
                estimated_egress_cost_micros: 0,
            },
            MultipathCandidate {
                path_id: "safe-baseline".to_owned(),
                kind: PathKind::LanPeer,
                failure_domain: "dom-safe".to_owned(),
                residency_zone: "local".to_owned(),
                privacy_authorized: true,
                integrity_verified: true,
                estimated_latency_ms: 25,
                estimated_egress_cost_micros: 10,
            },
        ],
        TimestampNs(1_000),
        false,
    )?;
    assert_eq!(race.clamped_rejections().len(), 1);
    assert_eq!(
        race.launch_next_path(&race_auth, TimestampNs(1_100), false)?,
        "safe-baseline"
    );
    let win_state =
        race.declare_winner_with_bytes("safe-baseline", &race_auth, &payload, TimestampNs(1_200))?;
    assert_eq!(win_state, MultipathRaceState::Complete);
    emit_xfer_caplog(
        "XFER-INV-007",
        "unsafe_fast_path_clamped_safe_baseline_selected",
        "ok",
    );

    // XFER-INV-009: Retention/deletion requires explicit graph closure & blocks under evidence hold!
    let src = d("held-source-chunk");
    let root = d("held-manifest-root");
    let mut catalog = ArchiveDeletionCatalog::new();
    catalog.insert(DeletionGraphNode {
        digest: src,
        class: DeletionArtifactClass::SourceChunk,
        byte_len: 4_096,
        custody: CustodyLevel::Durable,
        active_holds: BTreeSet::from(["legal-hold:case-2026".to_owned()]),
        dependencies: BTreeSet::new(),
        hidden_reference_aliases: BTreeSet::new(),
        reachable: true,
        simulate_surviving_hidden_ref: None,
    });
    catalog.insert(DeletionGraphNode {
        digest: root,
        class: DeletionArtifactClass::Manifest,
        byte_len: 512,
        custody: CustodyLevel::Durable,
        active_holds: BTreeSet::new(),
        dependencies: BTreeSet::from([src]),
        hidden_reference_aliases: BTreeSet::new(),
        reachable: true,
        simulate_surviving_hidden_ref: None,
    });
    let del_auth = DeletionAuthorityContext::approved(basis, 4, 1, d("owner-approval"));
    let held_plan = DeletionClosureExecutor::plan_closure(
        &catalog,
        root,
        &del_auth,
        Vec::new(),
        TimestampNs(2_000),
        false,
    )?;
    assert!(held_plan.is_blocked());
    let blocked = DeletionClosureExecutor::execute_and_verify(
        &mut catalog,
        &held_plan,
        &del_auth,
        &BTreeSet::new(),
        TimestampNs(2_100),
        false,
    );
    assert!(matches!(
        blocked,
        Err(DeletionClosureError::BlockedByHoldOrSharedReference { blocker_count: 1 })
    ));
    emit_xfer_caplog("XFER-INV-009", "legal_hold_blocks_deletion_closure", "ok");
    Ok(())
}
