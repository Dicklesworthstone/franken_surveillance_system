#![forbid(unsafe_code)]
//! Contract and fault suite for `FSS-131` (`fss-x4a.13.15`):
//! Archive replication-state and retrievability challenge ledger.

use std::collections::BTreeSet;

use fss_core::{ContentDigest, TimestampNs};
use fss_object::atp_lifecycle::ArchiveObjectState;
use fss_object::replication::{
    ArchiveReadinessState, ArchiveReplicationLedger, ChallengeOutcome, ChallengeRange,
    MAX_REPLICATION_LEDGER_WIRE_BYTES, REPLICATION_LEDGER_VERSION, RepairAction, ReplicaReadiness,
    ReplicationAuthorityContext, ReplicationError, ReplicationGuidance, ReplicationPolicy,
    RetrievabilityChallengeInput,
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

fn two_domain_policy() -> ReplicationPolicy {
    let mut required_providers = BTreeSet::new();
    required_providers.insert("s3:us-east-primary".to_owned());
    let mut allowed_residency_regions = BTreeSet::new();
    allowed_residency_regions.insert("us-east".to_owned());
    allowed_residency_regions.insert("us-west".to_owned());
    ReplicationPolicy {
        min_failure_domains: 2,
        required_providers,
        allowed_residency_regions,
        max_retrievability_staleness_ns: 3_600_000_000_000, // 1 hour
        policy_digest: d("policy:archive-two-domain-us:v1"),
    }
}

fn advance_to_published(
    ledger: &mut ArchiveReplicationLedger,
    auth: &ReplicationAuthorityContext,
    replica_id: &str,
    base_ts: i128,
) -> TestResult {
    let steps = [
        ArchiveObjectState::LocalDurable,
        ArchiveObjectState::RemoteStaged,
        ArchiveObjectState::RemoteChildrenVerified,
        ArchiveObjectState::RemoteRootPublished,
    ];
    for (idx, state) in steps.into_iter().enumerate() {
        ledger.advance_replica_custody(
            auth,
            replica_id,
            state,
            TimestampNs(base_ts + (idx as i128 + 1) * 1_000),
            false,
        )?;
    }
    Ok(())
}

#[test]
fn non_collapse_replication_ladder_retrievability_freshness_and_repair_loop() -> TestResult {
    let root = d("manifest:archive-root-131");
    let basis = d("contract-basis:131");
    let auth = ReplicationAuthorityContext::active(basis, 5, 2);
    let mut ledger = ArchiveReplicationLedger::new(root, basis, two_domain_policy())?;

    // Empty/staged ledger starts StagedOnly.
    assert_eq!(
        ledger.evaluate_readiness(TimestampNs(10_000)).state,
        ArchiveReadinessState::StagedOnly
    );

    // Residency clamp refuses unauthorized region before registration.
    let res_err = ledger
        .register_replica(
            &auth,
            "rep-eu",
            "s3:eu-central",
            "domain:eu-1",
            "eu-central",
            TimestampNs(10_000),
            false,
        )
        .expect_err("out-of-region replica must fail closed");
    assert!(matches!(res_err, ReplicationError::AuthorityRevoked(_)));
    assert_eq!(
        res_err.guidance(),
        ReplicationGuidance::ReauthorizeAndReanchor
    );

    // Register replica 1 in us-east.
    ledger.register_replica(
        &auth,
        "rep-east",
        "s3:us-east-primary",
        "domain:aws-east",
        "us-east",
        TimestampNs(10_000),
        false,
    )?;
    assert_eq!(
        ledger.evaluate_readiness(TimestampNs(10_000)).state,
        ArchiveReadinessState::StagedOnly
    );

    // Local durable != remote qualified.
    ledger.advance_replica_custody(
        &auth,
        "rep-east",
        ArchiveObjectState::LocalDurable,
        TimestampNs(11_000),
        false,
    )?;
    assert_eq!(
        ledger.evaluate_readiness(TimestampNs(11_000)).state,
        ArchiveReadinessState::LocalDurableOnly
    );

    // Root-last enforcement: skipping RemoteChildrenVerified fails closed.
    ledger.advance_replica_custody(
        &auth,
        "rep-east",
        ArchiveObjectState::RemoteStaged,
        TimestampNs(12_000),
        false,
    )?;
    let skip_err = ledger
        .advance_replica_custody(
            &auth,
            "rep-east",
            ArchiveObjectState::RemoteRootPublished,
            TimestampNs(13_000),
            false,
        )
        .expect_err("skipping remote_children_verified must fail");
    assert!(matches!(
        skip_err,
        ReplicationError::InvalidCustodyTransition { .. }
    ));
    assert_eq!(
        skip_err.guidance(),
        ReplicationGuidance::CompletePriorCustodyMilestone
    );

    // Complete rep-east publication; still RemoteUnqualified because only 1 failure domain exists.
    ledger.advance_replica_custody(
        &auth,
        "rep-east",
        ArchiveObjectState::RemoteChildrenVerified,
        TimestampNs(13_000),
        false,
    )?;
    ledger.advance_replica_custody(
        &auth,
        "rep-east",
        ArchiveObjectState::RemoteRootPublished,
        TimestampNs(14_000),
        false,
    )?;
    assert_eq!(
        ledger.evaluate_readiness(TimestampNs(14_000)).state,
        ArchiveReadinessState::RemoteUnqualified
    );
    assert!(
        ledger
            .advance_replica_custody(
                &auth,
                "rep-east",
                ArchiveObjectState::ReplicationPolicySatisfied,
                TimestampNs(15_000),
                false,
            )
            .is_err(),
        "1 domain cannot satisfy min_failure_domains = 2"
    );

    // Register & publish replica 2 in an independent failure domain (us-west).
    ledger.register_replica(
        &auth,
        "rep-west",
        "r2:us-west-secondary",
        "domain:cf-west",
        "us-west",
        TimestampNs(20_000),
        false,
    )?;
    advance_to_published(&mut ledger, &auth, "rep-west", 20_000)?;
    for rep in ["rep-east", "rep-west"] {
        ledger.advance_replica_custody(
            &auth,
            rep,
            ArchiveObjectState::ReplicationPolicySatisfied,
            TimestampNs(30_000),
            false,
        )?;
    }
    assert_eq!(
        ledger.evaluate_readiness(TimestampNs(30_000)).state,
        ArchiveReadinessState::PolicySatisfiedUnchallenged
    );

    // Direct advance to RetrievabilitySamplePassed without challenge proof fails closed.
    assert!(
        ledger
            .advance_replica_custody(
                &auth,
                "rep-east",
                ArchiveObjectState::RetrievabilitySamplePassed,
                TimestampNs(31_000),
                false,
            )
            .is_err()
    );

    // Record passing proof-of-retrievability challenges on both domains.
    let chal_east = RetrievabilityChallengeInput {
        challenge_id: "chal:east:001".to_owned(),
        replica_id: "rep-east".to_owned(),
        replica_generation: 1,
        ranges: vec![ChallengeRange {
            offset: 0,
            length: 4096,
        }],
        expected_digest: root,
        observed_digest: Some(root),
        latency_ms: 42,
        egress_bytes: 4096,
        class_b_ops: 1,
        outcome: ChallengeOutcome::Passed,
        challenged_at: TimestampNs(40_000),
    };
    let rc_east = ledger.record_challenge(&auth, chal_east.clone(), false)?;
    // Idempotent duplicate returns exact same receipt; conflicting ID fails closed.
    assert_eq!(
        ledger.record_challenge(&auth, chal_east.clone(), false)?,
        rc_east
    );
    let mut conflicting = chal_east;
    conflicting.latency_ms = 999;
    assert!(matches!(
        ledger.record_challenge(&auth, conflicting, false),
        Err(ReplicationError::DuplicateChallengeConflict { .. })
    ));

    // Projection to atp_lifecycle::ProofOfRetrievability validates cleanly.
    let por = rc_east
        .to_proof_of_retrievability()
        .ok_or("expected valid ProofOfRetrievability")?;
    por.validate_for(root)?;

    let chal_west = RetrievabilityChallengeInput {
        challenge_id: "chal:west:001".to_owned(),
        replica_id: "rep-west".to_owned(),
        replica_generation: 1,
        ranges: vec![ChallengeRange {
            offset: 4096,
            length: 4096,
        }],
        expected_digest: root,
        observed_digest: Some(root),
        latency_ms: 58,
        egress_bytes: 4096,
        class_b_ops: 1,
        outcome: ChallengeOutcome::Passed,
        challenged_at: TimestampNs(41_000),
    };
    ledger.record_challenge(&auth, chal_west, false)?;

    let fresh = ledger.evaluate_readiness(TimestampNs(50_000));
    assert_eq!(fresh.state, ArchiveReadinessState::RetrievableFresh);
    assert_eq!(fresh.fresh_retrievable_domains.len(), 2);
    assert_eq!(fresh.total_challenge_egress_bytes, 8192);
    assert_eq!(fresh.total_challenge_ops, 2);

    // Reordered older Passed challenge must NOT rewind last_verified_at backwards!
    ledger.record_challenge(
        &auth,
        RetrievabilityChallengeInput {
            challenge_id: "chal:east:000-late-reorder".to_owned(),
            replica_id: "rep-east".to_owned(),
            replica_generation: 1,
            ranges: vec![ChallengeRange {
                offset: 0,
                length: 1024,
            }],
            expected_digest: root,
            observed_digest: Some(root),
            latency_ms: 19,
            egress_bytes: 1024,
            class_b_ops: 1,
            outcome: ChallengeOutcome::Passed,
            challenged_at: TimestampNs(35_000),
        },
        false,
    )?;
    assert_eq!(
        ledger.replicas()["rep-east"].last_verified_at,
        Some(TimestampNs(40_000))
    );

    // Aging past max_retrievability_staleness_ns degrades honestly to RetrievabilityStale.
    let stale = ledger.evaluate_readiness(TimestampNs(40_000 + 4_000_000_000_000));
    assert_eq!(stale.state, ArchiveReadinessState::RetrievabilityStale);
    assert!(stale.fresh_retrievable_domains.is_empty());

    // Digest mismatch on rep-west quarantines replica, demotes custody, and opens repair obligation!
    let corrupt_chal = RetrievabilityChallengeInput {
        challenge_id: "chal:west:002-corrupt".to_owned(),
        replica_id: "rep-west".to_owned(),
        replica_generation: 1,
        ranges: vec![ChallengeRange {
            offset: 0,
            length: 4096,
        }],
        expected_digest: root,
        observed_digest: Some(d("corrupt-bytes-bitrot")),
        latency_ms: 61,
        egress_bytes: 4096,
        class_b_ops: 1,
        outcome: ChallengeOutcome::DigestMismatch,
        challenged_at: TimestampNs(60_000),
    };
    let corrupt_rc = ledger.record_challenge(&auth, corrupt_chal, false)?;
    assert_eq!(corrupt_rc.repair_action, RepairAction::QuarantineAndRepair);
    assert!(corrupt_rc.to_proof_of_retrievability().is_none());
    assert_eq!(
        ledger.replicas()["rep-west"].readiness,
        ReplicaReadiness::Quarantined
    );
    assert_eq!(
        ledger.replicas()["rep-west"].custody_state,
        ArchiveObjectState::RemoteRootPublished
    );
    let degraded = ledger.evaluate_readiness(TimestampNs(61_000));
    assert_eq!(degraded.state, ArchiveReadinessState::RepairRequired);
    assert_eq!(degraded.open_repair_obligations, 1);

    // A later TimeoutOrIndeterminate sample on a Quarantined replica MUST NOT downgrade
    // Quarantined -> Indeterminate (which would otherwise allow a quarantine bypass!).
    ledger.record_challenge(
        &auth,
        RetrievabilityChallengeInput {
            challenge_id: "chal:west:timeout-after-quarantine".to_owned(),
            replica_id: "rep-west".to_owned(),
            replica_generation: 1,
            ranges: vec![ChallengeRange {
                offset: 0,
                length: 4096,
            }],
            expected_digest: root,
            observed_digest: None,
            latency_ms: 9_000,
            egress_bytes: 0,
            class_b_ops: 1,
            outcome: ChallengeOutcome::TimeoutOrIndeterminate,
            challenged_at: TimestampNs(63_000),
        },
        false,
    )?;
    assert_eq!(
        ledger.replicas()["rep-west"].readiness,
        ReplicaReadiness::Quarantined
    );

    // A quarantined generation 1 CANNOT silently clear quarantine via a Passed challenge without
    // rotating to a freshly repaired generation.
    assert!(matches!(
        ledger.record_challenge(
            &auth,
            RetrievabilityChallengeInput {
                challenge_id: "chal:west:bypass-quarantine".to_owned(),
                replica_id: "rep-west".to_owned(),
                replica_generation: 1,
                ranges: vec![ChallengeRange {
                    offset: 0,
                    length: 4096,
                }],
                expected_digest: root,
                observed_digest: Some(root),
                latency_ms: 25,
                egress_bytes: 4096,
                class_b_ops: 1,
                outcome: ChallengeOutcome::Passed,
                challenged_at: TimestampNs(65_000),
            },
            false,
        ),
        Err(ReplicationError::InvalidInput(_))
    ));

    // Repair loop: rotate rep-west to generation 2; both open obligations stay open until new gen passes proof!
    ledger.begin_replica_repair_generation(&auth, "rep-west", TimestampNs(70_000), false)?;
    assert_eq!(ledger.replicas()["rep-west"].replica_generation, 2);
    assert_eq!(
        ledger
            .evaluate_readiness(TimestampNs(70_000))
            .open_repair_obligations,
        2
    );
    for state in [
        ArchiveObjectState::RemoteChildrenVerified,
        ArchiveObjectState::RemoteRootPublished,
        ArchiveObjectState::ReplicationPolicySatisfied,
    ] {
        ledger.advance_replica_custody(&auth, "rep-west", state, TimestampNs(72_000), false)?;
    }
    // Stale generation 1 challenge on repaired replica fails closed!
    let stale_gen_err = ledger
        .record_challenge(
            &auth,
            RetrievabilityChallengeInput {
                challenge_id: "chal:west:stale-gen".to_owned(),
                replica_id: "rep-west".to_owned(),
                replica_generation: 1,
                ranges: vec![ChallengeRange {
                    offset: 0,
                    length: 1024,
                }],
                expected_digest: root,
                observed_digest: Some(root),
                latency_ms: 20,
                egress_bytes: 1024,
                class_b_ops: 1,
                outcome: ChallengeOutcome::Passed,
                challenged_at: TimestampNs(73_000),
            },
            false,
        )
        .expect_err("stale replica_generation must fail closed");
    assert!(matches!(
        stale_gen_err,
        ReplicationError::StaleReplicaGeneration {
            current: 2,
            supplied: 1,
            ..
        }
    ));

    // Passing challenge on generation 2 resolves repair obligation and restores RetrievableFresh!
    let repair_rc = ledger.record_challenge(
        &auth,
        RetrievabilityChallengeInput {
            challenge_id: "chal:west:003-repaired".to_owned(),
            replica_id: "rep-west".to_owned(),
            replica_generation: 2,
            ranges: vec![ChallengeRange {
                offset: 0,
                length: 4096,
            }],
            expected_digest: root,
            observed_digest: Some(root),
            latency_ms: 49,
            egress_bytes: 4096,
            class_b_ops: 1,
            outcome: ChallengeOutcome::Passed,
            challenged_at: TimestampNs(75_000),
        },
        false,
    )?;
    let restored = ledger.evaluate_readiness(TimestampNs(76_000));
    assert_eq!(restored.state, ArchiveReadinessState::RetrievableFresh);
    assert_eq!(restored.open_repair_obligations, 0);
    assert!(
        ledger
            .repair_obligations()
            .values()
            .all(|o| o.resolved && o.resolved_by_challenge_digest == Some(repair_rc.receipt_digest))
    );

    // Binary wire codec round-trip reproduces bit-identical ledger & head_digest.
    let wire = ledger.to_canonical_bytes()?;
    let decoded = ArchiveReplicationLedger::from_canonical_bytes(&wire)?;
    assert_eq!(decoded, ledger);
    assert_eq!(decoded.head_digest(), ledger.head_digest());

    emit_caplog(
        "fss131_replication_ladder_retrievability_and_repair",
        "non_collapse_freshness_quarantine_repair_and_wire_verified",
        "non_collapse_freshness_quarantine_repair_and_wire_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn indeterminate_authority_revocation_cancellation_and_hostile_wire_fail_closed() -> TestResult {
    let root = d("manifest:archive-root-131-faults");
    let basis = d("contract-basis:131-faults");
    let auth = ReplicationAuthorityContext::active(basis, 3, 1);
    let mut ledger = ArchiveReplicationLedger::new(root, basis, two_domain_policy())?;

    ledger.register_replica(
        &auth,
        "rep-east",
        "s3:us-east-primary",
        "domain:aws-east",
        "us-east",
        TimestampNs(1_000),
        false,
    )?;
    advance_to_published(&mut ledger, &auth, "rep-east", 1_000)?;
    let head_before = ledger.head_digest();

    // 1. Revoked capability, revoked privacy, stale generation, and cancellation leave ledger untouched.
    let mut revoked_cap = auth.clone();
    revoked_cap.capability_active = false;
    assert!(matches!(
        ledger.register_replica(
            &revoked_cap,
            "rep-west",
            "r2:us-west",
            "domain:cf-west",
            "us-west",
            TimestampNs(5_000),
            false,
        ),
        Err(ReplicationError::AuthorityRevoked(_))
    ));

    let mut stale_gen = auth.clone();
    stale_gen.authority_generation = 99;
    assert!(matches!(
        ledger.register_replica(
            &stale_gen,
            "rep-west",
            "r2:us-west",
            "domain:cf-west",
            "us-west",
            TimestampNs(5_000),
            false,
        ),
        Err(ReplicationError::StaleGenerationOrBasis {
            expected: 3,
            observed: 99
        })
    ));

    assert_eq!(
        ledger.register_replica(
            &auth,
            "rep-west",
            "r2:us-west",
            "domain:cf-west",
            "us-west",
            TimestampNs(5_000),
            true,
        ),
        Err(ReplicationError::Cancelled)
    );
    assert_eq!(ledger.head_digest(), head_before);

    // 2. Indeterminate challenge marks replica Indeterminate without upgrading readiness to healthy.
    let indet_rc = ledger.record_challenge(
        &auth,
        RetrievabilityChallengeInput {
            challenge_id: "chal:east:timeout".to_owned(),
            replica_id: "rep-east".to_owned(),
            replica_generation: 1,
            ranges: vec![ChallengeRange {
                offset: 0,
                length: 2048,
            }],
            expected_digest: root,
            observed_digest: None,
            latency_ms: 15_000,
            egress_bytes: 0,
            class_b_ops: 1,
            outcome: ChallengeOutcome::TimeoutOrIndeterminate,
            challenged_at: TimestampNs(6_000),
        },
        false,
    )?;
    assert_eq!(
        indet_rc.repair_action,
        RepairAction::ReconcileIndeterminateReplica
    );
    let summary = ledger.evaluate_readiness(TimestampNs(7_000));
    assert_eq!(summary.state, ArchiveReadinessState::Indeterminate);
    assert_eq!(summary.indeterminate_replicas, 1);
    assert_eq!(summary.open_repair_obligations, 1);

    // A delayed older Passed challenge (challenged_at < opened_at) MUST NOT resolve the newer
    // open repair obligation or falsely mark the replica Healthy!
    ledger.record_challenge(
        &auth,
        RetrievabilityChallengeInput {
            challenge_id: "chal:east:pre-timeout-late-pass".to_owned(),
            replica_id: "rep-east".to_owned(),
            replica_generation: 1,
            ranges: vec![ChallengeRange {
                offset: 0,
                length: 2048,
            }],
            expected_digest: root,
            observed_digest: Some(root),
            latency_ms: 12,
            egress_bytes: 2048,
            class_b_ops: 1,
            outcome: ChallengeOutcome::Passed,
            challenged_at: TimestampNs(5_500),
        },
        false,
    )?;
    assert_eq!(
        ledger.replicas()["rep-east"].readiness,
        ReplicaReadiness::Indeterminate
    );
    assert_eq!(
        ledger
            .evaluate_readiness(TimestampNs(7_000))
            .open_repair_obligations,
        1
    );

    // Max-length 128-byte replica_id + 128-byte challenge_id produces a 264-byte obligation_id
    // that must round-trip cleanly through binary wire encode/decode.
    let long_rep = "r".repeat(128);
    let long_chal = "c".repeat(128);
    ledger.register_replica(
        &auth,
        &long_rep,
        "r2:us-west-long",
        "domain:cf-long",
        "us-west",
        TimestampNs(8_000),
        false,
    )?;
    ledger.record_challenge(
        &auth,
        RetrievabilityChallengeInput {
            challenge_id: long_chal,
            replica_id: long_rep,
            replica_generation: 1,
            ranges: vec![ChallengeRange {
                offset: 0,
                length: 512,
            }],
            expected_digest: root,
            observed_digest: None,
            latency_ms: 500,
            egress_bytes: 0,
            class_b_ops: 1,
            outcome: ChallengeOutcome::MissingOrTruncated,
            challenged_at: TimestampNs(8_500),
        },
        false,
    )?;

    // 3. Forged Passed challenge (zero bytes or mismatched observed_digest) fails closed.
    assert!(matches!(
        ledger.record_challenge(
            &auth,
            RetrievabilityChallengeInput {
                challenge_id: "chal:east:forged-zero".to_owned(),
                replica_id: "rep-east".to_owned(),
                replica_generation: 1,
                ranges: vec![ChallengeRange {
                    offset: 0,
                    length: 512,
                }],
                expected_digest: root,
                observed_digest: Some(root),
                latency_ms: 5,
                egress_bytes: 0,
                class_b_ops: 1,
                outcome: ChallengeOutcome::Passed,
                challenged_at: TimestampNs(8_000),
            },
            false,
        ),
        Err(ReplicationError::InvalidInput(_))
    ));

    // 4. Hostile wire payloads fail closed.
    let wire = ledger.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        ArchiveReplicationLedger::from_canonical_bytes(&bad_magic),
        Err(ReplicationError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&(REPLICATION_LEDGER_VERSION + 1).to_be_bytes());
    assert_eq!(
        ArchiveReplicationLedger::from_canonical_bytes(&bad_ver),
        Err(ReplicationError::UnsupportedVersion {
            version: REPLICATION_LEDGER_VERSION + 1
        })
    );
    assert!(matches!(
        ArchiveReplicationLedger::from_canonical_bytes(&wire[..wire.len() - 5]),
        Err(ReplicationError::MalformedWire(_))
    ));
    let mut flipped = wire.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x08;
    assert_eq!(
        ArchiveReplicationLedger::from_canonical_bytes(&flipped),
        Err(ReplicationError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0x42);
    assert!(matches!(
        ArchiveReplicationLedger::from_canonical_bytes(&trailing),
        Err(ReplicationError::MalformedWire(_))
    ));
    let huge = vec![0u8; MAX_REPLICATION_LEDGER_WIRE_BYTES + 1];
    assert!(matches!(
        ArchiveReplicationLedger::from_canonical_bytes(&huge),
        Err(ReplicationError::BoundsExceeded { .. })
    ));

    emit_caplog(
        "fss131_faults_indeterminate_auth_cancel_wire",
        "all_replication_faults_and_wire_checks_failed_closed",
        "all_replication_faults_and_wire_checks_failed_closed",
        "pass",
    );
    Ok(())
}

#[test]
fn root_readiness_and_repair_follow_the_evidence_target_after_restart() -> TestResult {
    let root = d("root:readiness-target");
    let object = d("object:range-a");
    let basis = d("basis:readiness-target");
    let auth = ReplicationAuthorityContext::active(basis, 5, 2);
    let mut policy = two_domain_policy();
    policy.min_failure_domains = 1;
    policy.max_retrievability_staleness_ns = 100;
    let mut ledger = ArchiveReplicationLedger::new(root, basis, policy)?;
    for (replica, provider, domain) in [
        ("primary", "s3:us-east-primary", "east"),
        ("extra", "r2:us-west-secondary", "west"),
    ] {
        ledger.register_replica(
            &auth,
            replica,
            provider,
            domain,
            "us-east",
            TimestampNs(0),
            false,
        )?;
        advance_to_published(&mut ledger, &auth, replica, 0)?;
    }
    let sample = |id: &str, replica: &str, expected, at| RetrievabilityChallengeInput {
        challenge_id: id.to_owned(),
        replica_id: replica.to_owned(),
        replica_generation: 1,
        ranges: vec![ChallengeRange {
            offset: 0,
            length: 64,
        }],
        expected_digest: expected,
        observed_digest: Some(expected),
        latency_ms: 4,
        egress_bytes: 64,
        class_b_ops: 1,
        outcome: ChallengeOutcome::Passed,
        challenged_at: TimestampNs(at),
    };

    ledger.record_challenge(&auth, sample("extra-root", "extra", root, 5000), false)?;
    let range =
        ledger.record_challenge(&auth, sample("primary-range", "primary", object, 5001), false)?;
    assert!(range.to_proof_of_retrievability().is_none());
    let decoded = ArchiveReplicationLedger::from_canonical_bytes(&ledger.to_canonical_bytes()?)?;
    assert_eq!(decoded, ledger);
    let missing_root = decoded.evaluate_readiness(TimestampNs(5002));
    assert_eq!(
        missing_root.state,
        ArchiveReadinessState::PolicySatisfiedUnchallenged
    );
    assert_eq!(
        missing_root.fresh_retrievable_domains,
        BTreeSet::from(["west".to_owned()])
    );
    assert_eq!(missing_root.total_challenge_egress_bytes, 128);

    let root_receipt =
        ledger.record_challenge(&auth, sample("primary-root", "primary", root, 5010), false)?;
    let mut different_domain = root_receipt.clone();
    different_domain.failure_domain = "other".to_owned();
    assert!(different_domain.to_proof_of_retrievability().is_none());
    assert_eq!(
        ledger.evaluate_readiness(TimestampNs(5011)).state,
        ArchiveReadinessState::RetrievableFresh
    );

    let timeout = RetrievabilityChallengeInput {
        outcome: ChallengeOutcome::TimeoutOrIndeterminate,
        observed_digest: None,
        egress_bytes: 0,
        ..sample("extra-timeout", "extra", root, 5020)
    };
    ledger.record_challenge(&auth, timeout, false)?;
    ledger.record_challenge(&auth, sample("extra-object", "extra", object, 5030), false)?;
    let unresolved = ArchiveReplicationLedger::from_canonical_bytes(&ledger.to_canonical_bytes()?)?
        .evaluate_readiness(TimestampNs(5031));
    assert_eq!(unresolved.state, ArchiveReadinessState::Indeterminate);
    assert_eq!(unresolved.open_repair_obligations, 1);

    ledger.record_challenge(&auth, sample("extra-repaired", "extra", root, 5040), false)?;
    ledger.record_challenge(
        &auth,
        sample("primary-late-range", "primary", object, 5105),
        false,
    )?;
    // The range neither supersedes a still-fresh root proof nor extends its lifetime.
    assert_eq!(
        ledger.evaluate_readiness(TimestampNs(5105)).state,
        ArchiveReadinessState::RetrievableFresh
    );
    let decoded = ArchiveReplicationLedger::from_canonical_bytes(&ledger.to_canonical_bytes()?)?;
    let after_expiry = decoded.evaluate_readiness(TimestampNs(5111));
    assert_eq!(
        after_expiry.state,
        ArchiveReadinessState::RetrievabilityStale
    );
    assert_eq!(
        after_expiry.fresh_retrievable_domains,
        BTreeSet::from(["west".to_owned()])
    );
    assert_eq!(after_expiry.open_repair_obligations, 0);
    Ok(())
}
