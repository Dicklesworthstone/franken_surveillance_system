#![forbid(unsafe_code)]
//! Integration and contract tests for the event evidence graph and revision store (FSS-081).
//!
//! Enforces:
//! - Append-only monotonic revisions and non-rewriting history
//! - Anchor-pinned commits and stale anchor rejection
//! - Exact rebuildability of all derived state from canonical history alone (INV-015)
//! - First-class contradictions and unresolved worlds preservation (INV-002)
//! - Explicit coverage boundaries: reads outside coverage return typed NotObservable, never absence (INV-055)
//! - Attached evidence graph indexing and validation
//! - Hard capacity bounds tested at exact bound and bound+1

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::Debug;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    Completeness, ContentDigest, ContractError, Contradiction, ContradictionParams,
    CoverageContinuity, CoverageStopReason, CoverageWitness, DecisionPath, EventEvidence,
    EventHypothesis, EventId, EventKind, EventReadResult, EventRevisionStore, EventState,
    EventStoreCommit, EventStoreEntry, EventStoreError, EventTransitionParams, EvidenceClass,
    EvidenceEdgeRelation, EvidenceGraph, EvidenceNode, EvidenceNodeKind, GraphReadResult,
    HypothesisDisposition, KnowledgeState, LedgerAnchor, LineageReadResult,
    MAX_CONTRADICTIONS_PER_EVENT, MAX_GRAPHS_PER_REVISION, MAX_STORE_LINEAGE_DEPTH,
    NotObservableReason, ProbabilityInterval, ProvenanceClass, RuntimeOutcome, TimestampNs,
};

type TestResult = Result<(), Box<dyn Error>>;

fn expect_err<T: Debug>(
    result: Result<T, EventStoreError>,
) -> Result<EventStoreError, Box<dyn Error>> {
    match result {
        Ok(value) => Err(format!("expected an event store error, got {value:?}").into()),
        Err(err) => Ok(err),
    }
}

fn sample_genesis(event_id: &str) -> Result<EventHypothesis, Box<dyn Error>> {
    let interval = CaptureInterval::new(TimestampNs(1_000_000_000), TimestampNs(1_005_000_000))?;
    let evidence = vec![EventEvidence {
        digest: ContentDigest::sha256(b"genesis-evidence-root-sensor-1"),
        class: EvidenceClass::Observed,
        failure_domain: "sensor.cam_01".to_string(),
        relation: EvidenceEdgeRelation::Supports,
        supports: true,
        capsule_digest: None,
        identity_digest: None,
    }];
    let decision_path = DecisionPath {
        policy_generation: ContentDigest::sha256(b"policy:test-v1"),
        fingerprint: ContentDigest::sha256(b"fingerprint:test-v1"),
        abstained: false,
        abstention_reason: None,
    };
    let probability = ProbabilityInterval::new(0.3, 0.8)?;
    Ok(EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_string(),
        event_id: EventId::parse(event_id)?,
        revision: 1,
        supersedes: None,
        state: EventState::Hypothesized,
        kind: EventKind::PerimeterBreach,
        interval,
        uncertainty_reason: None,
        zone_ids: vec!["perimeter_north".to_string()],
        track_ids: vec!["track_001".to_string()],
        probability,
        evidence,
        model_receipts: vec![],
        decision_path,
    })
}

fn sample_graph(
    event_id: &str,
    graph_id: &str,
    revision: u64,
) -> Result<EvidenceGraph, Box<dyn Error>> {
    let root_digest = ContentDigest::sha256(graph_id.as_bytes());
    let nodes = vec![EvidenceNode {
        digest: root_digest,
        kind: EvidenceNodeKind::Observation,
        label: "cam_north_capsule".to_string(),
        failure_domain: "sensor.cam_01".to_string(),
    }];
    let edges = vec![EventEvidence {
        digest: root_digest,
        class: EvidenceClass::Observed,
        failure_domain: "sensor.cam_01".to_string(),
        relation: EvidenceEdgeRelation::Supports,
        supports: true,
        capsule_digest: None,
        identity_digest: None,
    }];
    Ok(EvidenceGraph {
        schema: EvidenceGraph::SCHEMA.to_string(),
        graph_id: graph_id.to_string(),
        event_id: EventId::parse(event_id)?,
        revision,
        root_digest,
        nodes,
        edges,
    })
}

fn sample_contradiction(
    contradiction_id: &str,
    claim_id: &str,
    worlds: &[&str],
) -> Result<Contradiction, Box<dyn Error>> {
    sample_contradiction_with_disposition(
        contradiction_id,
        claim_id,
        worlds,
        HypothesisDisposition::Live,
    )
}

fn sample_contradiction_with_disposition(
    contradiction_id: &str,
    claim_id: &str,
    worlds: &[&str],
    disposition: HypothesisDisposition,
) -> Result<Contradiction, Box<dyn Error>> {
    let mut unresolved_worlds = BTreeSet::new();
    for w in worlds {
        unresolved_worlds.insert((*w).to_string());
    }
    let mut conflicting_evidence = BTreeSet::new();
    conflicting_evidence.insert(ContentDigest::sha256(b"sensor-1-evidence-root"));
    conflicting_evidence.insert(ContentDigest::sha256(b"sensor-2-evidence-root"));
    let mut failure_domains = BTreeSet::new();
    failure_domains.insert("sensor.cam_01".to_string());
    failure_domains.insert("sensor.cam_02".to_string());

    let params = ContradictionParams {
        contradiction_id: contradiction_id.to_string(),
        conflicting_evidence,
        failure_domains,
        unresolved_worlds,
        claim_id: Some(claim_id.to_string()),
        statement: "conflicting spatial-temporal target tracking between sensors".to_string(),
        belief_interval: None,
        created_at: TimestampNs(1_006_000_000),
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::Derived,
        disposition,
        outcome: RuntimeOutcome::Indeterminate,
    };
    Contradiction::new(params).map_err(|e| Box::new(e) as Box<dyn Error>)
}

fn sample_coverage_witness(
    domain: &str,
    continuous: bool,
    complete: bool,
    excluded: bool,
) -> Result<CoverageWitness, Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("test-site-lineage");
    let mut observed = BTreeSet::new();
    observed.insert(domain.to_string());
    let mut authorized = BTreeSet::new();
    authorized.insert(domain.to_string());
    let mut exclusions = BTreeSet::new();
    if excluded {
        exclusions.insert(domain.to_string());
    }

    Ok(CoverageWitness {
        anchor,
        authorized_domain: authorized,
        observed_domain: observed,
        excluded_domain: exclusions,
        continuity: if continuous {
            CoverageContinuity::Continuous
        } else {
            CoverageContinuity::Gapped
        },
        completeness: if complete {
            Completeness::Complete
        } else {
            Completeness::Partial
        },
        negative_predicate: "no_unauthorized_intrusion".to_string(),
        stop_reason: if complete {
            CoverageStopReason::Complete
        } else {
            CoverageStopReason::SourceGap
        },
        authorized_generation: 1,
        observed_generation: 1,
    })
}

// ---------------------------------------------------------------------------------------------
// Criterion 1: Append-Only Monotonic Revisions and Non-Rewriting History
// ---------------------------------------------------------------------------------------------

#[test]
fn criterion_1_append_only_monotonic_revisions_and_non_rewriting_history() -> TestResult {
    let genesis_anchor = LedgerAnchor::genesis("site-perimeter-alpha");
    let mut store = EventRevisionStore::new(genesis_anchor.clone());
    let event_id = "evt_perimeter_001";
    let genesis = sample_genesis(event_id)?;
    let ev_id = EventId::parse(event_id)?;

    // Append genesis revision 1
    let commit_time_1 = TimestampNs(1_005_000_000);
    let digest_1 = store.append_genesis(
        genesis_anchor.clone(),
        genesis.clone(),
        "perimeter.north",
        commit_time_1,
    )?;
    assert_eq!(store.commit_count(), 1);
    assert_eq!(store.event_count(), 1);
    assert_ne!(digest_1, ContentDigest::sha256(b""));

    // Attempting to append genesis again for same event fails with NonMonotonicRevision
    let err_dup = expect_err(store.append_genesis(
        store.current_anchor().clone(),
        genesis.clone(),
        "perimeter.north",
        commit_time_1,
    ))?;
    assert!(matches!(
        err_dup,
        EventStoreError::NonMonotonicRevision { .. }
    ));

    // Append transition to Witnessed (revision 2)
    let anchor_2 = store.current_anchor().clone();
    let transition_params = EventTransitionParams {
        target_state: EventState::Witnessed,
        kind: EventKind::PerimeterBreach,
        interval: CaptureInterval::new(TimestampNs(1_000_000_000), TimestampNs(1_006_000_000))?,
        uncertainty_reason: None,
        zone_ids: vec!["perimeter_north".to_string()],
        track_ids: vec!["track_001".to_string()],
        probability: ProbabilityInterval::new(0.5, 0.9)?,
        evidence: vec![
            EventEvidence {
                digest: ContentDigest::sha256(b"genesis-evidence-root-sensor-1"),
                class: EvidenceClass::Observed,
                failure_domain: "sensor.cam_01".to_string(),
                relation: EvidenceEdgeRelation::Supports,
                supports: true,
                capsule_digest: None,
                identity_digest: None,
            },
            EventEvidence {
                digest: ContentDigest::sha256(b"witness-evidence-root-sensor-1"),
                class: EvidenceClass::Observed,
                failure_domain: "sensor.cam_01".to_string(),
                relation: EvidenceEdgeRelation::Supports,
                supports: true,
                capsule_digest: None,
                identity_digest: None,
            },
        ],
        model_receipts: vec![],
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(b"policy:test-v1"),
            fingerprint: ContentDigest::sha256(b"fingerprint:test-v2"),
            abstained: false,
            abstention_reason: None,
        },
        urgent_single_sensor: false,
    };
    let commit_time_2 = TimestampNs(1_006_000_000);
    let digest_2 = store.append_transition(anchor_2, &ev_id, transition_params, commit_time_2)?;
    assert_eq!(store.commit_count(), 2);
    assert_ne!(digest_1, digest_2);

    // Verify history contains both revisions, unchanged
    let read_rev1 = store.read_event(&ev_id, Some(1))?;
    match read_rev1 {
        EventReadResult::Found(rev) => {
            assert_eq!(rev.revision, 1);
            assert_eq!(rev.state, EventState::Hypothesized);
        }
        other => return Err(format!("expected Found for rev 1, got {other:?}").into()),
    }

    let read_rev2 = store.read_event(&ev_id, Some(2))?;
    match read_rev2 {
        EventReadResult::Found(rev) => {
            assert_eq!(rev.revision, 2);
            assert_eq!(rev.state, EventState::Witnessed);
            assert_eq!(
                rev.supersedes,
                Some(genesis.canonical_digest(EventHypothesis::SCHEMA))
            );
        }
        other => return Err(format!("expected Found for rev 2, got {other:?}").into()),
    }

    // Attempting a non-monotonic revision number directly fails closed
    let anchor_3 = store.current_anchor().clone();
    let mut bad_rev = genesis.clone();
    bad_rev.revision = 5; // Expected 3
    bad_rev.supersedes = Some(ContentDigest::sha256(b"random"));
    let err_non_mono =
        expect_err(store.append_revision(anchor_3, bad_rev, TimestampNs(1_007_000_000)))?;
    assert!(matches!(
        err_non_mono,
        EventStoreError::NonMonotonicRevision {
            expected: 3,
            actual: 5,
            ..
        }
    ));

    // Transition to Rejected (terminal state)
    let anchor_term = store.current_anchor().clone();
    let term_params = EventTransitionParams {
        target_state: EventState::Rejected,
        kind: EventKind::PerimeterBreach,
        interval: CaptureInterval::new(TimestampNs(1_000_000_000), TimestampNs(1_006_000_000))?,
        uncertainty_reason: Some("disproved by operator verification".to_string()),
        zone_ids: vec!["perimeter_north".to_string()],
        track_ids: vec!["track_001".to_string()],
        probability: ProbabilityInterval::new(0.0, 0.05)?,
        evidence: vec![EventEvidence {
            digest: ContentDigest::sha256(b"operator-rejection-proof"),
            class: EvidenceClass::Observed,
            failure_domain: "operator.station_alpha".to_string(),
            relation: EvidenceEdgeRelation::Contradicts,
            supports: false,
            capsule_digest: None,
            identity_digest: None,
        }],
        model_receipts: vec![],
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(b"policy:test-v1"),
            fingerprint: ContentDigest::sha256(b"fingerprint:test-v3"),
            abstained: false,
            abstention_reason: None,
        },
        urgent_single_sensor: false,
    };
    store.append_transition(anchor_term, &ev_id, term_params, TimestampNs(1_007_000_000))?;
    assert_eq!(store.commit_count(), 3);

    // Terminal state cannot be superseded
    let anchor_after_term = store.current_anchor().clone();
    let follow_params = EventTransitionParams {
        target_state: EventState::Resolved,
        kind: EventKind::PerimeterBreach,
        interval: CaptureInterval::new(TimestampNs(1_000_000_000), TimestampNs(1_006_000_000))?,
        uncertainty_reason: None,
        zone_ids: vec![],
        track_ids: vec![],
        probability: ProbabilityInterval::new(0.0, 0.0)?,
        evidence: vec![EventEvidence {
            digest: ContentDigest::sha256(b"follow-resolution-proof"),
            class: EvidenceClass::Observed,
            failure_domain: "operator.station_alpha".to_string(),
            relation: EvidenceEdgeRelation::Supports,
            supports: true,
            capsule_digest: None,
            identity_digest: None,
        }],
        model_receipts: vec![],
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(b"policy:test-v1"),
            fingerprint: ContentDigest::sha256(b"fingerprint:test-v4"),
            abstained: false,
            abstention_reason: None,
        },
        urgent_single_sensor: false,
    };
    let err_term = expect_err(store.append_transition(
        anchor_after_term,
        &ev_id,
        follow_params,
        TimestampNs(1_008_000_000),
    ))?;
    assert!(matches!(
        err_term,
        EventStoreError::TerminalStateImmutable {
            state: EventState::Rejected,
            ..
        }
    ));

    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Criterion 2: Anchor Pinning and Stale Anchor Rejection
// ---------------------------------------------------------------------------------------------

#[test]
fn criterion_2_anchor_pinning_and_stale_anchor_rejection() -> TestResult {
    let genesis_anchor = LedgerAnchor::genesis("site-anchor-pinning");
    let mut store = EventRevisionStore::new(genesis_anchor.clone());
    let genesis = sample_genesis("evt_anchor_test_01")?;

    // Commit 1 advances anchor
    store.append_genesis(
        genesis_anchor.clone(),
        genesis,
        "coverage.zone_a",
        TimestampNs(1_000),
    )?;
    let current_anchor = store.current_anchor().clone();
    assert_eq!(current_anchor.commit_sequence, 1);
    assert_ne!(current_anchor.state_root, genesis_anchor.state_root);

    // Attempting commit with old genesis_anchor fails closed with StaleAnchor
    let diverged_genesis = sample_genesis("evt_anchor_test_02")?;
    let err_stale = expect_err(store.append_genesis(
        genesis_anchor.clone(),
        diverged_genesis.clone(),
        "coverage.zone_a",
        TimestampNs(2_000),
    ))?;
    match err_stale {
        EventStoreError::StaleAnchor { expected, actual } => {
            assert_eq!(expected.commit_sequence, 1);
            assert_eq!(actual.commit_sequence, 0);
        }
        other => return Err(format!("expected StaleAnchor, got {other:?}").into()),
    }

    // Rebased commit using current_anchor succeeds
    store.append_genesis(
        current_anchor,
        diverged_genesis,
        "coverage.zone_a",
        TimestampNs(2_000),
    )?;
    assert_eq!(store.commit_count(), 2);
    assert_eq!(store.current_anchor().commit_sequence, 2);

    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Criterion 3: Rebuildability from Canonical History (INV-015)
// ---------------------------------------------------------------------------------------------

#[test]
fn criterion_3_rebuildability_from_canonical_history() -> TestResult {
    let genesis_anchor = LedgerAnchor::genesis("site-rebuild-test");
    let mut store = EventRevisionStore::new(genesis_anchor.clone());

    // 1. Genesis event 1
    let ev1 = EventId::parse("evt_rebuild_01")?;
    let gen1 = sample_genesis("evt_rebuild_01")?;
    store.append_genesis(
        store.current_anchor().clone(),
        gen1,
        "domain.alpha",
        TimestampNs(1_000),
    )?;

    // 2. Attach evidence graph
    let graph = sample_graph("evt_rebuild_01", "graph_001", 1)?;
    store.attach_evidence_graph(store.current_anchor().clone(), graph, TimestampNs(2_000))?;

    // 3. Record contradiction
    let contradiction = sample_contradiction(
        "contra_001",
        "evt_rebuild_01",
        &["world.presence", "world.absence"],
    )?;
    store.record_contradiction(
        store.current_anchor().clone(),
        ev1.clone(),
        contradiction,
        TimestampNs(3_000),
    )?;

    // 4. Register coverage witness
    let witness = sample_coverage_witness("domain.alpha", true, true, false)?;
    store.register_coverage_witness(store.current_anchor().clone(), witness, TimestampNs(4_000))?;

    // 5. Genesis event 2
    let gen2 = sample_genesis("evt_rebuild_02")?;
    store.append_genesis(
        store.current_anchor().clone(),
        gen2,
        "domain.beta",
        TimestampNs(5_000),
    )?;

    assert_eq!(store.commit_count(), 5);
    assert_eq!(store.event_count(), 2);
    assert_eq!(store.unresolved_worlds().len(), 2);

    // Rebuild from history
    let history_slice = store.history().to_vec();
    let rebuilt = EventRevisionStore::rebuild_from_history(genesis_anchor.clone(), &history_slice)?;

    // Assert exact equality between original and rebuilt store
    assert_eq!(rebuilt, store);
    assert_eq!(rebuilt.current_anchor(), store.current_anchor());
    assert_eq!(rebuilt.commit_count(), 5);
    assert_eq!(rebuilt.event_count(), 2);
    assert_eq!(rebuilt.unresolved_worlds(), store.unresolved_worlds());

    // Verifying tamper detection in history replay: flipped bit in commit sequence
    let mut tampered_history = history_slice.clone();
    tampered_history[2].sequence = 999;
    let err_tamper = expect_err(EventRevisionStore::rebuild_from_history(
        genesis_anchor.clone(),
        &tampered_history,
    ))?;
    assert!(matches!(
        err_tamper,
        EventStoreError::SequenceNotMonotonic {
            expected: 3,
            actual: 999
        }
    ));

    // Tampered basis anchor fails closed
    let mut tampered_anchor = history_slice.clone();
    tampered_anchor[1].basis_anchor = genesis_anchor.clone(); // Stale anchor
    let err_tamper_anchor = expect_err(EventRevisionStore::rebuild_from_history(
        genesis_anchor,
        &tampered_anchor,
    ))?;
    assert!(matches!(
        err_tamper_anchor,
        EventStoreError::StaleAnchor { .. }
    ));

    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Criterion 4: First-Class Contradictions & Unresolved Worlds (INV-002)
// ---------------------------------------------------------------------------------------------

#[test]
fn criterion_4_first_class_contradictions_and_unresolved_worlds_preserved() -> TestResult {
    let genesis_anchor = LedgerAnchor::genesis("site-contradictions");
    let mut store = EventRevisionStore::new(genesis_anchor);
    let ev_id = EventId::parse("evt_contra_test")?;
    let genesis = sample_genesis("evt_contra_test")?;
    store.append_genesis(
        store.current_anchor().clone(),
        genesis,
        "domain.gamma",
        TimestampNs(1_000),
    )?;

    assert!(!store.has_contradiction(&ev_id));
    assert!(store.unresolved_worlds().is_empty());

    // Record contradiction 1 with 2 unresolved worlds
    let contra1 = sample_contradiction(
        "contra_alpha",
        "evt_contra_test",
        &["world.loiter", "world.transit"],
    )?;
    store.record_contradiction(
        store.current_anchor().clone(),
        ev_id.clone(),
        contra1,
        TimestampNs(2_000),
    )?;

    assert!(store.has_contradiction(&ev_id));
    assert_eq!(store.contradictions_for_event(&ev_id).len(), 1);
    assert!(store.is_world_unresolved("world.loiter"));
    assert!(store.is_world_unresolved("world.transit"));
    assert!(!store.is_world_unresolved("world.authorized_crew"));

    // Record contradiction 2 adding a 3rd unresolved world
    let contra2 = sample_contradiction(
        "contra_beta",
        "evt_contra_test",
        &["world.loiter", "world.authorized_crew"],
    )?;
    store.record_contradiction(
        store.current_anchor().clone(),
        ev_id.clone(),
        contra2,
        TimestampNs(3_000),
    )?;

    assert_eq!(store.contradictions_for_event(&ev_id).len(), 2);
    assert_eq!(store.unresolved_worlds().len(), 3);
    assert!(store.is_world_unresolved("world.loiter"));
    assert!(store.is_world_unresolved("world.transit"));
    assert!(store.is_world_unresolved("world.authorized_crew"));

    // Attempting to record an invalid contradiction (< 2 conflicting roots) fails closed
    let mut bad_conflicting_evidence = BTreeSet::new();
    bad_conflicting_evidence.insert(ContentDigest::sha256(b"only-one-root")); // < 2 roots!
    let mut bad_failure_domains = BTreeSet::new();
    bad_failure_domains.insert("sensor.cam_01".to_string());
    bad_failure_domains.insert("sensor.cam_02".to_string());
    let mut bad_unresolved_worlds = BTreeSet::new();
    bad_unresolved_worlds.insert("world.one".to_string());

    let bad_contra_params = ContradictionParams {
        contradiction_id: "bad_contra".to_string(),
        conflicting_evidence: bad_conflicting_evidence,
        failure_domains: bad_failure_domains,
        unresolved_worlds: bad_unresolved_worlds,
        claim_id: Some("evt_contra_test".to_string()),
        statement: "statement".to_string(),
        belief_interval: None,
        created_at: TimestampNs(4_000),
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::Derived,
        disposition: HypothesisDisposition::Live,
        outcome: RuntimeOutcome::Indeterminate,
    };
    let bad_contra = Contradiction::new(bad_contra_params);
    assert!(bad_contra.is_err());

    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Criterion 5: Coverage Boundary & Explicit Not-Observable State (INV-055)
// ---------------------------------------------------------------------------------------------

#[test]
fn criterion_5_explicit_coverage_boundary_and_not_observable_reads() -> TestResult {
    let genesis_anchor = LedgerAnchor::genesis("site-coverage");
    let mut store = EventRevisionStore::new(genesis_anchor);

    let present_id = EventId::parse("evt_present_01")?;
    let absent_id = EventId::parse("evt_absent_02")?;
    let genesis = sample_genesis("evt_present_01")?;

    store.append_genesis(
        store.current_anchor().clone(),
        genesis,
        "domain.monitored_gate",
        TimestampNs(1_000),
    )?;

    // 1. Querying an event that exists returns Found
    match store.read_event(&present_id, None)? {
        EventReadResult::Found(rev) => assert_eq!(rev.revision, 1),
        other => return Err(format!("expected Found, got {other:?}").into()),
    }

    // 2. Querying an event outside coverage (no CoverageWitness) returns NotObservable, NEVER absence/None!
    match store.read_event(&absent_id, None)? {
        EventReadResult::NotObservable { domain, reason } => {
            assert_eq!(domain, "unknown");
            assert_eq!(reason, NotObservableReason::UnknownDomain);
        }
        other => {
            return Err(format!("expected NotObservable with UnknownDomain, got {other:?}").into());
        }
    }

    // Querying with an explicit domain without coverage witness
    match store.read_event_in_domain(&absent_id, "domain.monitored_gate", None)? {
        EventReadResult::NotObservable { domain, reason } => {
            assert_eq!(domain, "domain.monitored_gate");
            assert_eq!(reason, NotObservableReason::NoCoverageWitness);
        }
        other => return Err(format!("expected NotObservable, got {other:?}").into()),
    }

    // 3. Register a valid CoverageWitness certifying absence for "domain.monitored_gate"
    let witness = sample_coverage_witness("domain.monitored_gate", true, true, false)?;
    store.register_coverage_witness(
        store.current_anchor().clone(),
        witness.clone(),
        TimestampNs(2_000),
    )?;

    // Now reading absent_id in "domain.monitored_gate" returns AbsentWithCoverage!
    match store.read_event_in_domain(&absent_id, "domain.monitored_gate", None)? {
        EventReadResult::AbsentWithCoverage(w) => {
            assert_eq!(w.authorized_domain, witness.authorized_domain);
            assert!(w.certifies_absence());
        }
        other => return Err(format!("expected AbsentWithCoverage, got {other:?}").into()),
    }

    // Reading lineage for absent event in domain also returns AbsentWithCoverage
    match store.read_lineage_in_domain(&absent_id, "domain.monitored_gate")? {
        LineageReadResult::AbsentWithCoverage(w) => {
            assert!(w.certifies_absence());
        }
        other => return Err(format!("expected AbsentWithCoverage, got {other:?}").into()),
    }

    // 4. Register a gapped coverage witness for "domain.gapped_gate"
    let gapped_witness = sample_coverage_witness("domain.gapped_gate", false, true, false)?;
    store.register_coverage_witness(
        store.current_anchor().clone(),
        gapped_witness,
        TimestampNs(3_000),
    )?;

    // Querying in gapped domain returns NotObservable with CoverageWitnessGapped, NEVER absence!
    let gapped_id = EventId::parse("evt_gapped_03")?;
    match store.read_event_in_domain(&gapped_id, "domain.gapped_gate", None)? {
        EventReadResult::NotObservable { domain, reason } => {
            assert_eq!(domain, "domain.gapped_gate");
            assert_eq!(reason, NotObservableReason::CoverageWitnessGapped);
        }
        other => {
            return Err(format!(
                "expected NotObservable with CoverageWitnessGapped, got {other:?}"
            )
            .into());
        }
    }

    // 5. Register an uncertified coverage witness for "domain.partial_gate"
    let partial_witness = sample_coverage_witness("domain.partial_gate", true, false, false)?;
    store.register_coverage_witness(
        store.current_anchor().clone(),
        partial_witness,
        TimestampNs(4_000),
    )?;

    match store.read_event_in_domain(&absent_id, "domain.partial_gate", None)? {
        EventReadResult::NotObservable { domain, reason } => {
            assert_eq!(domain, "domain.partial_gate");
            assert_eq!(reason, NotObservableReason::CoverageWitnessUncertified);
        }
        other => {
            return Err(format!(
                "expected NotObservable with CoverageWitnessUncertified, got {other:?}"
            )
            .into());
        }
    }

    // 6. Register an excluded domain witness
    let excluded_witness = sample_coverage_witness("domain.excluded_gate", true, true, true)?;
    store.register_coverage_witness(
        store.current_anchor().clone(),
        excluded_witness,
        TimestampNs(5_000),
    )?;

    match store.read_event_in_domain(&absent_id, "domain.excluded_gate", None)? {
        EventReadResult::NotObservable { domain, reason } => {
            assert_eq!(domain, "domain.excluded_gate");
            assert_eq!(
                reason,
                NotObservableReason::ExcludedDomain {
                    domain: "domain.excluded_gate".to_string()
                }
            );
        }
        other => {
            return Err(
                format!("expected NotObservable with ExcludedDomain, got {other:?}").into(),
            );
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Criterion 6: Evidence Graph Attachment and Indexing
// ---------------------------------------------------------------------------------------------

#[test]
fn criterion_6_evidence_graph_attachment_and_indexing() -> TestResult {
    let genesis_anchor = LedgerAnchor::genesis("site-graphs");
    let mut store = EventRevisionStore::new(genesis_anchor);
    let ev_id = EventId::parse("evt_graph_test")?;
    let genesis = sample_genesis("evt_graph_test")?;
    store.append_genesis(
        store.current_anchor().clone(),
        genesis,
        "domain.graphs",
        TimestampNs(1_000),
    )?;

    // Attach graph 1 to revision 1
    let graph1 = sample_graph("evt_graph_test", "graph_alpha", 1)?;
    store.attach_evidence_graph(
        store.current_anchor().clone(),
        graph1.clone(),
        TimestampNs(2_000),
    )?;

    // Attach graph 2 to revision 1
    let graph2 = sample_graph("evt_graph_test", "graph_beta", 1)?;
    store.attach_evidence_graph(
        store.current_anchor().clone(),
        graph2.clone(),
        TimestampNs(3_000),
    )?;

    // Read attached graphs for revision 1
    let graphs = store.read_evidence_graphs(&ev_id, 1)?;
    assert_eq!(graphs.len(), 2);
    assert_eq!(graphs[0].graph_id, "graph_alpha");
    assert_eq!(graphs[1].graph_id, "graph_beta");

    // Read single graph by id
    match store.read_evidence_graph("graph_alpha", "domain.graphs")? {
        GraphReadResult::Found(g) => assert_eq!(g.graph_id, "graph_alpha"),
        other => return Err(format!("expected Found, got {other:?}").into()),
    }

    // Read non-existent graph outside coverage returns NotObservable
    match store.read_evidence_graph("graph_nonexistent", "domain.unobserved")? {
        GraphReadResult::NotObservable { domain, reason } => {
            assert_eq!(domain, "domain.unobserved");
            assert_eq!(reason, NotObservableReason::NoCoverageWitness);
        }
        other => return Err(format!("expected NotObservable, got {other:?}").into()),
    }

    // Attaching duplicate graph ID fails closed
    let err_dup = expect_err(store.attach_evidence_graph(
        store.current_anchor().clone(),
        graph1,
        TimestampNs(4_000),
    ))?;
    assert!(matches!(err_dup, EventStoreError::DuplicateGraphId(id) if id == "graph_alpha"));

    // Attaching graph to non-existent revision fails closed
    let graph_rev5 = sample_graph("evt_graph_test", "graph_rev5", 5)?;
    let err_rev = expect_err(store.attach_evidence_graph(
        store.current_anchor().clone(),
        graph_rev5,
        TimestampNs(5_000),
    ))?;
    assert!(matches!(
        err_rev,
        EventStoreError::RevisionNotFound { revision: 5, .. }
    ));

    // Attaching graph to non-existent event fails closed
    let graph_other = sample_graph("evt_unknown", "graph_other", 1)?;
    let err_event = expect_err(store.attach_evidence_graph(
        store.current_anchor().clone(),
        graph_other,
        TimestampNs(6_000),
    ))?;
    assert!(matches!(err_event, EventStoreError::EventNotFound(..)));

    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Criterion 7: Hard Bounds at Bound and Bound+1
// ---------------------------------------------------------------------------------------------

#[test]
fn criterion_7_hard_bounds_at_bound_and_bound_plus_one() -> TestResult {
    let genesis_anchor = LedgerAnchor::genesis("site-bounds");
    let mut store = EventRevisionStore::new(genesis_anchor);
    let ev_id = EventId::parse("evt_bounds_test")?;
    let genesis = sample_genesis("evt_bounds_test")?;
    store.append_genesis(
        store.current_anchor().clone(),
        genesis,
        "domain.bounds",
        TimestampNs(1_000),
    )?;

    // 1. Evidence graphs per revision limit: MAX_GRAPHS_PER_REVISION (64)
    for i in 0..MAX_GRAPHS_PER_REVISION {
        let gid = format!("g_bound_{i:04}");
        let graph = sample_graph("evt_bounds_test", &gid, 1)?;
        store.attach_evidence_graph(
            store.current_anchor().clone(),
            graph,
            TimestampNs(2_000 + i as i128),
        )?;
    }
    assert_eq!(
        store.read_evidence_graphs(&ev_id, 1)?.len(),
        MAX_GRAPHS_PER_REVISION
    );

    // Bound + 1 rejected
    let overflow_graph = sample_graph("evt_bounds_test", "g_overflow", 1)?;
    let err_g_limit = expect_err(store.attach_evidence_graph(
        store.current_anchor().clone(),
        overflow_graph,
        TimestampNs(3_000),
    ))?;
    assert!(matches!(
        err_g_limit,
        EventStoreError::GraphCapacityExceeded {
            limit: 64,
            actual: 65,
            ..
        }
    ));

    // 2. Contradictions per event limit: MAX_CONTRADICTIONS_PER_EVENT (64)
    for i in 0..MAX_CONTRADICTIONS_PER_EVENT {
        let cid = format!("c_bound_{i:04}");
        let world = format!("world_{i}");
        let contra = sample_contradiction(&cid, "evt_bounds_test", &[&world, "world.shared"])?;
        store.record_contradiction(
            store.current_anchor().clone(),
            ev_id.clone(),
            contra,
            TimestampNs(4_000 + i as i128),
        )?;
    }
    assert_eq!(
        store.contradictions_for_event(&ev_id).len(),
        MAX_CONTRADICTIONS_PER_EVENT
    );

    // Bound + 1 rejected
    let overflow_contra = sample_contradiction("c_overflow", "evt_bounds_test", &["w.a", "w.b"])?;
    let err_c_limit = expect_err(store.record_contradiction(
        store.current_anchor().clone(),
        ev_id.clone(),
        overflow_contra,
        TimestampNs(5_000),
    ))?;
    assert!(matches!(
        err_c_limit,
        EventStoreError::ContradictionCapacityExceeded {
            limit: 64,
            actual: 65,
            ..
        }
    ));

    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Criterion 8: Deterministic Canonical Commit Digests
// ---------------------------------------------------------------------------------------------

#[test]
fn criterion_8_deterministic_canonical_commit_digests() -> TestResult {
    let genesis_anchor = LedgerAnchor::genesis("site-determinism");
    let mut store_a = EventRevisionStore::new(genesis_anchor.clone());
    let mut store_b = EventRevisionStore::new(genesis_anchor);

    let genesis_a = sample_genesis("evt_det_01")?;
    let genesis_b = sample_genesis("evt_det_01")?;

    let digest_a = store_a.append_genesis(
        store_a.current_anchor().clone(),
        genesis_a,
        "domain.det",
        TimestampNs(10_000),
    )?;
    let digest_b = store_b.append_genesis(
        store_b.current_anchor().clone(),
        genesis_b,
        "domain.det",
        TimestampNs(10_000),
    )?;

    assert_eq!(digest_a, digest_b);
    assert_eq!(store_a.current_anchor(), store_b.current_anchor());

    let graph_a = sample_graph("evt_det_01", "g_det", 1)?;
    let graph_b = sample_graph("evt_det_01", "g_det", 1)?;

    let g_digest_a = store_a.attach_evidence_graph(
        store_a.current_anchor().clone(),
        graph_a,
        TimestampNs(20_000),
    )?;
    let g_digest_b = store_b.attach_evidence_graph(
        store_b.current_anchor().clone(),
        graph_b,
        TimestampNs(20_000),
    )?;

    assert_eq!(g_digest_a, g_digest_b);
    assert_eq!(store_a.current_anchor(), store_b.current_anchor());
    assert_eq!(store_a, store_b);

    Ok(())
}

#[test]
fn unknown_domain_never_yields_absent_with_coverage() -> TestResult {
    let genesis_anchor = LedgerAnchor::genesis("site-coverage-unknown-check");
    let mut store = EventRevisionStore::new(genesis_anchor);

    // Register a CoverageWitness that observes domain "unknown" and certifies absence
    let witness = sample_coverage_witness("unknown", true, true, false)?;

    store.register_coverage_witness(store.current_anchor().clone(), witness, TimestampNs(1_000))?;

    // An event that was never registered has no known domain.
    // Querying it must NEVER return AbsentWithCoverage, even if a witness observed "unknown"!
    let unknown_id = EventId::parse("evt:test:unknown_never_registered")?;

    match store.read_event(&unknown_id, None)? {
        EventReadResult::NotObservable { domain, reason } => {
            assert_eq!(domain, "unknown");
            assert_eq!(reason, NotObservableReason::UnknownDomain);
        }
        EventReadResult::AbsentWithCoverage(_) => {
            return Err("absence claimed without known coverage domain".into());
        }
        other => {
            return Err(format!("expected NotObservable with UnknownDomain, got {other:?}").into());
        }
    }

    match store.read_lineage(&unknown_id)? {
        LineageReadResult::NotObservable { domain, reason } => {
            assert_eq!(domain, "unknown");
            assert_eq!(reason, NotObservableReason::UnknownDomain);
        }
        LineageReadResult::AbsentWithCoverage(_) => {
            return Err("lineage absence claimed without known coverage domain".into());
        }
        other => {
            return Err(format!("expected NotObservable with UnknownDomain, got {other:?}").into());
        }
    }

    // Querying with an explicitly empty domain in read_event_in_domain must also return NotObservable(UnknownDomain)
    match store.read_event_in_domain(&unknown_id, "", None)? {
        EventReadResult::NotObservable { domain, reason } => {
            assert_eq!(domain, "");
            assert_eq!(reason, NotObservableReason::UnknownDomain);
        }
        EventReadResult::AbsentWithCoverage(_) => {
            return Err("absence claimed for empty domain".into());
        }
        other => {
            return Err(format!("expected NotObservable with UnknownDomain, got {other:?}").into());
        }
    }

    // Querying with domain "unknown" in read_event_in_domain must also return NotObservable(UnknownDomain)
    match store.read_event_in_domain(&unknown_id, "unknown", None)? {
        EventReadResult::NotObservable { domain, reason } => {
            assert_eq!(domain, "unknown");
            assert_eq!(reason, NotObservableReason::UnknownDomain);
        }
        EventReadResult::AbsentWithCoverage(_) => {
            return Err("absence claimed for unknown domain".into());
        }
        other => {
            return Err(format!("expected NotObservable with UnknownDomain, got {other:?}").into());
        }
    }

    Ok(())
}

#[test]
fn test_missing_revision_of_existing_event_must_not_return_absent_with_coverage() -> TestResult {
    let genesis_anchor = LedgerAnchor::genesis("site-test");
    let mut store = EventRevisionStore::new(genesis_anchor.clone());
    let genesis = sample_genesis("evt_present_001")?;
    store.append_genesis(
        genesis_anchor,
        genesis,
        "domain.monitored_gate",
        TimestampNs(1_000),
    )?;
    let witness = sample_coverage_witness("domain.monitored_gate", true, true, false)?;
    store.register_coverage_witness(store.current_anchor().clone(), witness, TimestampNs(2_000))?;

    let present_id = EventId::parse("evt_present_001")?;
    let result = store.read_event(&present_id, Some(999))?;
    assert!(
        !matches!(result, EventReadResult::AbsentWithCoverage(_)),
        "non-existent revision of an existing event must not return AbsentWithCoverage; got: {result:?}"
    );

    let domain_result =
        store.read_event_in_domain(&present_id, "domain.monitored_gate", Some(999))?;
    assert!(
        !matches!(domain_result, EventReadResult::AbsentWithCoverage(_)),
        "non-existent revision in read_event_in_domain must not return AbsentWithCoverage; got: {domain_result:?}"
    );
    Ok(())
}

#[test]
fn test_rebuild_from_history_must_fail_on_corrupt_commit_digest() -> TestResult {
    let genesis_anchor = LedgerAnchor::genesis("site-test");
    let mut store = EventRevisionStore::new(genesis_anchor.clone());
    let genesis = sample_genesis("evt_rebuild_001")?;
    store.append_genesis(
        genesis_anchor.clone(),
        genesis,
        "domain.test",
        TimestampNs(1_000),
    )?;

    let mut corrupted_history = store.history().to_vec();
    corrupted_history[0].commit_digest = ContentDigest::sha256(b"tampered_or_forged_digest");

    let res = EventRevisionStore::rebuild_from_history(genesis_anchor, &corrupted_history);
    assert!(
        res.is_err(),
        "rebuild_from_history must fail closed when commit_digest does not match commit contents"
    );
    Ok(())
}

#[test]
fn test_read_evidence_graphs_nonexistent_revision_returns_revision_not_found() -> TestResult {
    let genesis_anchor = LedgerAnchor::genesis("site-test");
    let mut store = EventRevisionStore::new(genesis_anchor.clone());
    let genesis = sample_genesis("evt_graph_001")?;
    store.append_genesis(genesis_anchor, genesis, "domain.test", TimestampNs(1_000))?;

    let event_id = EventId::parse("evt_graph_001")?;
    let res = store.read_evidence_graphs(&event_id, 999);
    assert!(
        matches!(
            res,
            Err(EventStoreError::RevisionNotFound { revision: 999, .. })
        ),
        "read_evidence_graphs must return RevisionNotFound for uncommitted revision, not Ok(vec![]), got: {res:?}"
    );
    Ok(())
}

#[test]
fn test_rebuild_state_root_mismatch_returns_dedicated_error() -> TestResult {
    let genesis_anchor = LedgerAnchor::genesis("site-test");
    let mut store = EventRevisionStore::new(genesis_anchor.clone());
    let genesis = sample_genesis("evt_anchor_001")?;
    store.append_genesis(
        genesis_anchor.clone(),
        genesis,
        "domain.test",
        TimestampNs(1_000),
    )?;

    let mut corrupted_history = store.history().to_vec();
    corrupted_history[0].new_anchor = LedgerAnchor::genesis("divergent-site");

    let res = EventRevisionStore::rebuild_from_history(genesis_anchor, &corrupted_history);
    assert!(
        !matches!(res, Err(EventStoreError::StaleAnchor { .. })),
        "rebuild successor anchor mismatch must emit a state root divergence error, not StaleAnchor, got: {res:?}"
    );
    Ok(())
}

#[test]
fn test_append_revision_at_max_depth_returns_lineage_depth_exceeded() -> TestResult {
    let genesis_anchor = LedgerAnchor::genesis("site-test");
    let mut store = EventRevisionStore::new(genesis_anchor.clone());
    let genesis = sample_genesis("evt_depth_001")?;
    let event_id = genesis.event_id.clone();
    store.append_genesis(genesis_anchor, genesis, "domain.test", TimestampNs(1_000))?;

    // Append transitions up to MAX_STORE_LINEAGE_DEPTH
    for i in 1..MAX_STORE_LINEAGE_DEPTH {
        let params = EventTransitionParams {
            target_state: EventState::Indeterminate,
            kind: EventKind::PerimeterBreach,
            interval: CaptureInterval::new(
                TimestampNs(1_000_000_000 + i as i128),
                TimestampNs(1_005_000_000 + i as i128),
            )?,
            uncertainty_reason: Some("ongoing tracking".to_string()),
            zone_ids: vec![],
            track_ids: vec![],
            probability: ProbabilityInterval::new(0.5, 0.5)?,
            evidence: vec![EventEvidence {
                digest: ContentDigest::sha256(format!("evidence-{i}").as_bytes()),
                class: EvidenceClass::Observed,
                failure_domain: "sensor.cam_01".to_string(),
                relation: EvidenceEdgeRelation::Supports,
                supports: true,
                capsule_digest: None,
                identity_digest: None,
            }],
            model_receipts: vec![],
            decision_path: DecisionPath {
                policy_generation: ContentDigest::sha256(b"policy:test-v1"),
                fingerprint: ContentDigest::sha256(format!("fingerprint-{i}").as_bytes()),
                abstained: false,
                abstention_reason: None,
            },
            urgent_single_sensor: false,
        };
        store.append_transition(
            store.current_anchor().clone(),
            &event_id,
            params,
            TimestampNs(2_000_000_000 + i as i128),
        )?;
    }

    assert_eq!(store.commit_count(), MAX_STORE_LINEAGE_DEPTH);

    // Now lineage is at MAX_STORE_LINEAGE_DEPTH. An append_revision must fail with LineageDepthExceeded!
    let current = store.read_event(&event_id, None)?;
    let EventReadResult::Found(current_hyp) = current else {
        return Err("expected Found".into());
    };
    let next_hyp = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_string(),
        event_id: event_id.clone(),
        revision: current_hyp.revision + 1,
        supersedes: Some(current_hyp.canonical_digest(EventHypothesis::SCHEMA)),
        state: EventState::Indeterminate,
        kind: EventKind::PerimeterBreach,
        interval: current_hyp.interval,
        uncertainty_reason: Some("ongoing tracking".to_string()),
        zone_ids: vec![],
        track_ids: vec![],
        probability: ProbabilityInterval::new(0.5, 0.5)?,
        evidence: vec![EventEvidence {
            digest: ContentDigest::sha256(b"overflow-evidence"),
            class: EvidenceClass::Observed,
            failure_domain: "sensor.cam_01".to_string(),
            relation: EvidenceEdgeRelation::Supports,
            supports: true,
            capsule_digest: None,
            identity_digest: None,
        }],
        model_receipts: vec![],
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(b"policy:test-v1"),
            fingerprint: ContentDigest::sha256(b"fingerprint:overflow"),
            abstained: false,
            abstention_reason: None,
        },
    };

    let res = store.append_revision(
        store.current_anchor().clone(),
        next_hyp,
        TimestampNs(99_000_000_000),
    );
    assert!(
        matches!(res, Err(EventStoreError::LineageDepthExceeded { .. })),
        "append_revision at max lineage depth must return LineageDepthExceeded, got: {res:?}"
    );
    Ok(())
}

#[test]
fn test_commit_and_entry_must_support_canonical_decode() -> TestResult {
    // 1. EventStoreEntry::GenesisRevision
    let genesis = sample_genesis("evt_decode_001")?;
    let entry_genesis = EventStoreEntry::GenesisRevision {
        revision: genesis.clone(),
        coverage_domain: "domain.test".to_string(),
    };
    let mut encoder = CanonicalEncoder::new();
    entry_genesis.encode_canonical(&mut encoder);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let decoded_entry = EventStoreEntry::decode_canonical(&mut decoder)
        .map_err(|e| format!("decode_canonical for GenesisRevision failed: {e:?}"))?;
    assert!(decoder.is_empty());
    assert_eq!(decoded_entry, entry_genesis);

    // 2. EventStoreEntry::RegisterCoverageWitness
    let witness = sample_coverage_witness("domain.test", true, true, false)?;
    let entry_witness = EventStoreEntry::RegisterCoverageWitness {
        witness: witness.clone(),
    };
    let mut encoder = CanonicalEncoder::new();
    entry_witness.encode_canonical(&mut encoder);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let decoded_witness_entry = EventStoreEntry::decode_canonical(&mut decoder)
        .map_err(|e| format!("decode_canonical for RegisterCoverageWitness failed: {e:?}"))?;
    assert!(decoder.is_empty());
    assert_eq!(decoded_witness_entry, entry_witness);

    // 3. EventStoreCommit
    let anchor_basis = LedgerAnchor::genesis("site-test");
    let mut anchor_new = anchor_basis.clone();
    anchor_new.commit_sequence = 1;
    let commit = EventStoreCommit {
        sequence: 1,
        basis_anchor: anchor_basis,
        new_anchor: anchor_new,
        commit_time: TimestampNs(1_000_000),
        entry: entry_genesis,
        commit_digest: ContentDigest::sha256(b"test-commit-digest"),
    };

    let mut encoder = CanonicalEncoder::new();
    commit.encode_canonical(&mut encoder);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let decoded_commit = EventStoreCommit::decode_canonical(&mut decoder)
        .map_err(|e| format!("decode_canonical for EventStoreCommit failed: {e:?}"))?;
    assert!(decoder.is_empty());
    assert_eq!(decoded_commit, commit);

    Ok(())
}

// ---------------------------------------------------------------------------------------------
// fss-8yptk N3: decode error identity, unknown-domain guard normalization, full tag round trip
// ---------------------------------------------------------------------------------------------

#[test]
fn test_unknown_entry_tag_returns_dedicated_error() -> TestResult {
    for tag in [0_u8, 6, 7, 255] {
        let mut encoder = CanonicalEncoder::new();
        encoder.u8(tag);
        encoder.text("trailing-payload");
        let bytes = encoder.finish();
        let err = match EventStoreEntry::from_canonical_bytes(&bytes) {
            Ok(entry) => {
                return Err(format!("tag {tag} must not decode, got {entry:?}").into());
            }
            Err(err) => err,
        };
        assert_ne!(
            err,
            ContractError::InvalidIdentifier,
            "tag {tag}: an unknown entry tag is not an identifier failure"
        );
        assert_eq!(err.code(), "unknown_entry_tag", "tag {tag}: got {err:?}");
        assert_eq!(err, ContractError::UnknownEntryTag(tag));
    }
    Ok(())
}

#[test]
fn test_unknown_domain_guard_is_case_and_whitespace_insensitive() -> TestResult {
    for domain in ["Unknown", "UNKNOWN", " unknown", "unknown\t", " UnKnOwN \n"] {
        let mut store = EventRevisionStore::new(LedgerAnchor::genesis("site-unknown-variants"));
        // A witness that observes the spelled-out domain and would otherwise certify absence.
        let witness = sample_coverage_witness(domain, true, true, false)?;
        assert!(witness.certifies_absence());
        store.register_coverage_witness(
            store.current_anchor().clone(),
            witness,
            TimestampNs(1_000),
        )?;
        let absent_id = EventId::parse("evt_unknown_variant_absent")?;

        match store.read_event_in_domain(&absent_id, domain, None)? {
            EventReadResult::NotObservable {
                domain: reported,
                reason,
            } => {
                assert_eq!(reported, domain);
                assert_eq!(reason, NotObservableReason::UnknownDomain, "{domain:?}");
            }
            other => {
                return Err(format!(
                    "read_event_in_domain({domain:?}) must be NotObservable(UnknownDomain), got {other:?}"
                )
                .into());
            }
        }

        match store.read_lineage_in_domain(&absent_id, domain)? {
            LineageReadResult::NotObservable {
                domain: reported,
                reason,
            } => {
                assert_eq!(reported, domain);
                assert_eq!(reason, NotObservableReason::UnknownDomain, "{domain:?}");
            }
            other => {
                return Err(format!(
                    "read_lineage_in_domain({domain:?}) must be NotObservable(UnknownDomain), got {other:?}"
                )
                .into());
            }
        }

        match store.read_evidence_graph("graph_unknown_variant_absent", domain)? {
            GraphReadResult::NotObservable {
                domain: reported,
                reason,
            } => {
                assert_eq!(reported, domain);
                assert_eq!(reason, NotObservableReason::UnknownDomain, "{domain:?}");
            }
            other => {
                return Err(format!(
                    "read_evidence_graph(_, {domain:?}) must be NotObservable(UnknownDomain), got {other:?}"
                )
                .into());
            }
        }
    }
    Ok(())
}

#[test]
fn test_every_entry_tag_round_trips_through_canonical_decode() -> TestResult {
    let genesis = sample_genesis("evt_decode_all_tags")?;
    let mut superseding = genesis.clone();
    superseding.revision = 2;
    superseding.supersedes = Some(ContentDigest::sha256(b"prior-revision-digest"));
    let entries = [
        (
            1_u8,
            EventStoreEntry::GenesisRevision {
                revision: genesis,
                coverage_domain: "domain.test".to_string(),
            },
        ),
        (
            2,
            EventStoreEntry::SupersedeRevision {
                revision: superseding,
            },
        ),
        (
            3,
            EventStoreEntry::AttachEvidenceGraph {
                graph: sample_graph("evt_decode_all_tags", "graph_decode_all_tags", 1)?,
            },
        ),
        (
            4,
            EventStoreEntry::RecordContradiction {
                event_id: EventId::parse("evt_decode_all_tags")?,
                contradiction: sample_contradiction(
                    "contradiction_decode_all_tags",
                    "claim_decode_all_tags",
                    &["world_a", "world_b"],
                )?,
            },
        ),
        (
            5,
            EventStoreEntry::RegisterCoverageWitness {
                witness: sample_coverage_witness("domain.test", true, true, false)?,
            },
        ),
    ];
    for (tag, entry) in entries {
        let bytes = entry.canonical_bytes();
        assert_eq!(bytes.first(), Some(&tag), "entry tag for {entry:?}");
        let decoded = EventStoreEntry::from_canonical_bytes(&bytes)
            .map_err(|e| format!("tag {tag} failed to decode: {e:?}"))?;
        assert_eq!(decoded, entry, "tag {tag} decoded to a different entry");
        assert_eq!(
            decoded.canonical_bytes(),
            bytes,
            "tag {tag} re-encoding must reproduce the input bytes"
        );
    }
    Ok(())
}

#[test]
fn has_contradiction_counts_only_active_contradictions() -> TestResult {
    let mut store = EventRevisionStore::new(LedgerAnchor::genesis("site-retired-contradictions"));
    let ev_id = EventId::parse("evt_retired_contra")?;
    store.append_genesis(
        store.current_anchor().clone(),
        sample_genesis("evt_retired_contra")?,
        "domain.gamma",
        TimestampNs(1_000),
    )?;

    // Every terminal disposition retires the contradiction: it stays recorded but is not active.
    let retired = [
        HypothesisDisposition::Refuted,
        HypothesisDisposition::Resolved,
        HypothesisDisposition::Superseded,
    ];
    for (index, disposition) in retired.into_iter().enumerate() {
        let contradiction = sample_contradiction_with_disposition(
            &format!("contra_retired_{index}"),
            "evt_retired_contra",
            &["world.loiter"],
            disposition,
        )?;
        store.record_contradiction(
            store.current_anchor().clone(),
            ev_id.clone(),
            contradiction,
            TimestampNs(2_000 + i128::try_from(index)?),
        )?;
        assert!(
            !store.has_contradiction(&ev_id),
            "a {disposition:?} contradiction must not count as active"
        );
    }
    assert_eq!(store.contradictions_for_event(&ev_id).len(), retired.len());

    // Any non-terminal disposition keeps the event contradicted.
    for (index, disposition) in [
        HypothesisDisposition::Disfavored,
        HypothesisDisposition::Supported,
        HypothesisDisposition::Live,
    ]
    .into_iter()
    .enumerate()
    {
        let mut probe = store.clone();
        let contradiction = sample_contradiction_with_disposition(
            &format!("contra_active_{index}"),
            "evt_retired_contra",
            &["world.transit"],
            disposition,
        )?;
        probe.record_contradiction(
            probe.current_anchor().clone(),
            ev_id.clone(),
            contradiction,
            TimestampNs(3_000 + i128::try_from(index)?),
        )?;
        assert!(
            probe.has_contradiction(&ev_id),
            "a {disposition:?} contradiction must count as active"
        );
    }
    Ok(())
}
