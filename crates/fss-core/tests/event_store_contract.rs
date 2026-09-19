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
    MAX_CONTRADICTIONS_PER_EVENT, MAX_GRAPHS_PER_REVISION, MAX_STORE_COMMITS,
    MAX_STORE_COVERAGE_WITNESSES, MAX_STORE_LINEAGE_DEPTH, NotObservableReason,
    ProbabilityInterval, ProvenanceClass, RuntimeOutcome, TimestampNs,
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
        EventReadResult::NotObservable { domain, reason, .. } => {
            assert_eq!(domain, "unknown");
            assert_eq!(reason, NotObservableReason::UnknownDomain);
        }
        other => {
            return Err(format!("expected NotObservable with UnknownDomain, got {other:?}").into());
        }
    }

    // Querying with an explicit domain without coverage witness
    match store.read_event_in_domain(&absent_id, "domain.monitored_gate", None)? {
        EventReadResult::NotObservable { domain, reason, .. } => {
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
        EventReadResult::NotObservable { domain, reason, .. } => {
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
        EventReadResult::NotObservable { domain, reason, .. } => {
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
        EventReadResult::NotObservable { domain, reason, .. } => {
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
        GraphReadResult::NotObservable { domain, reason, .. } => {
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
        EventReadResult::NotObservable { domain, reason, .. } => {
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
        LineageReadResult::NotObservable { domain, reason, .. } => {
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
        EventReadResult::NotObservable { domain, reason, .. } => {
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
        EventReadResult::NotObservable { domain, reason, .. } => {
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
    for tag in [0_u8, 7, 99, 255] {
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
                ..
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
                ..
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
                ..
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

#[test]
fn has_contradiction_agrees_with_unresolved_worlds_for_every_disposition() -> TestResult {
    let dispositions = [
        HypothesisDisposition::Live,
        HypothesisDisposition::Supported,
        HypothesisDisposition::Disfavored,
        HypothesisDisposition::Refuted,
        HypothesisDisposition::Resolved,
        HypothesisDisposition::Superseded,
    ];
    for (index, disposition) in dispositions.into_iter().enumerate() {
        // Exhaustive on purpose: a new disposition must choose whether it is active.
        let expected_active = match disposition {
            HypothesisDisposition::Live
            | HypothesisDisposition::Supported
            | HypothesisDisposition::Disfavored => true,
            HypothesisDisposition::Refuted
            | HypothesisDisposition::Resolved
            | HypothesisDisposition::Superseded => false,
        };
        let mut store = EventRevisionStore::new(LedgerAnchor::genesis("site-contradiction-agree"));
        let ev_id = EventId::parse("evt_contra_agree")?;
        store.append_genesis(
            store.current_anchor().clone(),
            sample_genesis("evt_contra_agree")?,
            "domain.gamma",
            TimestampNs(1_000),
        )?;
        let world = format!("world.agree_{index}");
        let contradiction = sample_contradiction_with_disposition(
            &format!("contra_agree_{index}"),
            "evt_contra_agree",
            &[world.as_str()],
            disposition,
        )?;
        store.record_contradiction(
            store.current_anchor().clone(),
            ev_id.clone(),
            contradiction,
            TimestampNs(2_000),
        )?;

        assert_eq!(
            store.contradictions_for_event(&ev_id).len(),
            1,
            "a {disposition:?} contradiction must still be retained"
        );
        assert_eq!(
            store.has_contradiction(&ev_id),
            expected_active,
            "has_contradiction for a {disposition:?} contradiction"
        );
        assert_eq!(
            store.is_world_unresolved(&world),
            store.has_contradiction(&ev_id),
            "is_world_unresolved must agree with has_contradiction for {disposition:?}"
        );
        assert_eq!(
            store.unresolved_worlds().is_empty(),
            !expected_active,
            "unresolved worlds for a {disposition:?} contradiction"
        );
    }
    Ok(())
}

#[test]
fn retired_contradiction_never_hides_an_active_one_on_the_same_world() -> TestResult {
    let orders = [
        [HypothesisDisposition::Live, HypothesisDisposition::Refuted],
        [HypothesisDisposition::Refuted, HypothesisDisposition::Live],
    ];
    for (order_index, order) in orders.into_iter().enumerate() {
        let mut store = EventRevisionStore::new(LedgerAnchor::genesis("site-contradiction-mixed"));
        let ev_id = EventId::parse("evt_contra_mixed")?;
        store.append_genesis(
            store.current_anchor().clone(),
            sample_genesis("evt_contra_mixed")?,
            "domain.gamma",
            TimestampNs(1_000),
        )?;
        for (index, disposition) in order.into_iter().enumerate() {
            let contradiction = sample_contradiction_with_disposition(
                &format!("contra_mixed_{order_index}_{index}"),
                "evt_contra_mixed",
                &["world.shared"],
                disposition,
            )?;
            store.record_contradiction(
                store.current_anchor().clone(),
                ev_id.clone(),
                contradiction,
                TimestampNs(2_000 + i128::try_from(index)?),
            )?;
            let any_active = order[..=index].iter().any(|recorded| {
                matches!(
                    recorded,
                    HypothesisDisposition::Live
                        | HypothesisDisposition::Supported
                        | HypothesisDisposition::Disfavored
                )
            });
            assert_eq!(
                store.has_contradiction(&ev_id),
                any_active,
                "has_contradiction after {:?}",
                &order[..=index]
            );
            assert_eq!(
                store.is_world_unresolved("world.shared"),
                any_active,
                "shared world after {:?}",
                &order[..=index]
            );
        }
        assert_eq!(store.contradictions_for_event(&ev_id).len(), 2);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Criterion: ANY-GAP-WINS Order-Independent Coverage for Absence (fss-3qlsa)
// ---------------------------------------------------------------------------------------------

#[test]
fn coverage_for_absence_certifying_then_gapped_yields_gapped() -> TestResult {
    let mut store = EventRevisionStore::new(LedgerAnchor::genesis("site-coverage-order-1"));
    let absent_id = EventId::parse("evt_absent_test_01")?;
    let domain = "domain.monitored_gate";

    let certifying = sample_coverage_witness(domain, true, true, false)?;
    let gapped = sample_coverage_witness(domain, false, true, false)?;

    store.register_coverage_witness(
        store.current_anchor().clone(),
        certifying,
        TimestampNs(1_000),
    )?;
    store.register_coverage_witness(store.current_anchor().clone(), gapped, TimestampNs(2_000))?;

    // Certifying registered first, then gapped: must NOT yield AbsentWithCoverage.
    // ANY-GAP-WINS mandates CoverageWitnessGapped.
    let expected_reasons = vec![NotObservableReason::CoverageWitnessGapped];
    let result = store.read_event_in_domain(&absent_id, domain, None)?;
    assert_eq!(
        result,
        EventReadResult::NotObservable {
            domain: domain.to_string(),
            reason: NotObservableReason::CoverageWitnessGapped,
            all_reasons: expected_reasons.clone(),
        }
    );

    let lineage_result = store.read_lineage_in_domain(&absent_id, domain)?;
    assert_eq!(
        lineage_result,
        LineageReadResult::NotObservable {
            domain: domain.to_string(),
            reason: NotObservableReason::CoverageWitnessGapped,
            all_reasons: expected_reasons,
        }
    );
    Ok(())
}

#[test]
fn coverage_for_absence_gapped_then_certifying_yields_exact_same_gapped() -> TestResult {
    let mut store = EventRevisionStore::new(LedgerAnchor::genesis("site-coverage-order-2"));
    let absent_id = EventId::parse("evt_absent_test_02")?;
    let domain = "domain.monitored_gate";

    let gapped = sample_coverage_witness(domain, false, true, false)?;
    let certifying = sample_coverage_witness(domain, true, true, false)?;

    store.register_coverage_witness(store.current_anchor().clone(), gapped, TimestampNs(1_000))?;
    store.register_coverage_witness(
        store.current_anchor().clone(),
        certifying,
        TimestampNs(2_000),
    )?;

    // Gapped registered first, then certifying: must yield identical CoverageWitnessGapped.
    let expected_reasons = vec![NotObservableReason::CoverageWitnessGapped];
    let result = store.read_event_in_domain(&absent_id, domain, None)?;
    assert_eq!(
        result,
        EventReadResult::NotObservable {
            domain: domain.to_string(),
            reason: NotObservableReason::CoverageWitnessGapped,
            all_reasons: expected_reasons.clone(),
        }
    );

    let lineage_result = store.read_lineage_in_domain(&absent_id, domain)?;
    assert_eq!(
        lineage_result,
        LineageReadResult::NotObservable {
            domain: domain.to_string(),
            reason: NotObservableReason::CoverageWitnessGapped,
            all_reasons: expected_reasons,
        }
    );
    Ok(())
}

#[test]
fn coverage_for_absence_two_certifying_witnesses_yields_absent_with_coverage() -> TestResult {
    let mut store = EventRevisionStore::new(LedgerAnchor::genesis("site-coverage-two-cert"));
    let absent_id = EventId::parse("evt_absent_test_03")?;
    let domain = "domain.monitored_gate";

    let cert1 = sample_coverage_witness(domain, true, true, false)?;
    let mut cert2 = sample_coverage_witness(domain, true, true, false)?;
    cert2.negative_predicate = "no_unauthorized_vehicle".to_string();

    store.register_coverage_witness(store.current_anchor().clone(), cert1, TimestampNs(1_000))?;
    store.register_coverage_witness(store.current_anchor().clone(), cert2, TimestampNs(2_000))?;

    let result = store.read_event_in_domain(&absent_id, domain, None)?;
    match result {
        EventReadResult::AbsentWithCoverage(w) => {
            assert!(w.certifies_absence());
            assert!(w.observed_domain.contains(domain));
        }
        other => return Err(format!("expected AbsentWithCoverage, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn coverage_for_absence_different_domain_witness_does_not_affect_result() -> TestResult {
    let mut store = EventRevisionStore::new(LedgerAnchor::genesis("site-coverage-diff-domain"));
    let absent_id = EventId::parse("evt_absent_test_04")?;
    let domain_a = "domain.monitored_gate";
    let domain_b = "domain.other_gate";

    let cert_a = sample_coverage_witness(domain_a, true, true, false)?;
    let gapped_b = sample_coverage_witness(domain_b, false, true, false)?;

    store.register_coverage_witness(store.current_anchor().clone(), cert_a, TimestampNs(1_000))?;
    store.register_coverage_witness(
        store.current_anchor().clone(),
        gapped_b,
        TimestampNs(2_000),
    )?;

    // Query domain_a: the gap in domain_b must not affect domain_a
    let result_a = store.read_event_in_domain(&absent_id, domain_a, None)?;
    match result_a {
        EventReadResult::AbsentWithCoverage(w) => {
            assert!(w.certifies_absence());
            assert!(w.observed_domain.contains(domain_a));
        }
        other => {
            return Err(format!("expected AbsentWithCoverage for domain_a, got {other:?}").into());
        }
    }

    // Query domain_b: must observe CoverageWitnessGapped
    let result_b = store.read_event_in_domain(&absent_id, domain_b, None)?;
    assert_eq!(
        result_b,
        EventReadResult::NotObservable {
            domain: domain_b.to_string(),
            reason: NotObservableReason::CoverageWitnessGapped,
            all_reasons: vec![NotObservableReason::CoverageWitnessGapped],
        }
    );

    // Query unobserved domain_c: must observe NoCoverageWitness
    let result_c = store.read_event_in_domain(&absent_id, "domain.unobserved_gate", None)?;
    assert_eq!(
        result_c,
        EventReadResult::NotObservable {
            domain: "domain.unobserved_gate".to_string(),
            reason: NotObservableReason::NoCoverageWitness,
            all_reasons: vec![NotObservableReason::NoCoverageWitness],
        }
    );
    Ok(())
}

fn generate_permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.is_empty() {
        return vec![Vec::new()];
    }
    let mut result = Vec::new();
    for i in 0..items.len() {
        let mut rest = items.to_vec();
        let item = rest.remove(i);
        for sub in generate_permutations(&rest) {
            let mut perm = vec![item.clone()];
            perm.extend(sub);
            result.push(perm);
        }
    }
    result
}

#[test]
fn coverage_for_absence_permutation_order_invariance_contract() -> TestResult {
    let domain = "domain.monitored_gate";
    let absent_id = EventId::parse("evt_absent_perm")?;

    let cert1 = sample_coverage_witness(domain, true, true, false)?;
    let mut cert2 = sample_coverage_witness(domain, true, true, false)?;
    cert2.negative_predicate = "no_unauthorized_vehicle".to_string();

    let gapped = sample_coverage_witness(domain, false, true, false)?;
    let uncert = sample_coverage_witness(domain, true, false, false)?;

    // Scenario 1: Mixed set with 4 witnesses (2 certifying, 1 gapped, 1 uncertified)
    // ANY-GAP-WINS: All 24 permutations must produce CoverageWitnessGapped.
    let four_witnesses = vec![cert1.clone(), cert2.clone(), gapped.clone(), uncert.clone()];
    let perms_4 = generate_permutations(&four_witnesses);
    assert_eq!(perms_4.len(), 24);

    let expected_gapped = EventReadResult::NotObservable {
        domain: domain.to_string(),
        reason: NotObservableReason::CoverageWitnessGapped,
        all_reasons: vec![
            NotObservableReason::CoverageWitnessGapped,
            NotObservableReason::CoverageWitnessUncertified,
        ],
    };

    for (idx, perm) in perms_4.iter().enumerate() {
        let mut store = EventRevisionStore::new(LedgerAnchor::genesis("site-coverage-perm-4"));
        for (step, w) in perm.iter().enumerate() {
            store.register_coverage_witness(
                store.current_anchor().clone(),
                w.clone(),
                TimestampNs(1_000 + (step as i128) * 100),
            )?;
        }
        let result = store.read_event_in_domain(&absent_id, domain, None)?;
        assert_eq!(
            result, expected_gapped,
            "permutation {idx} must yield CoverageWitnessGapped regardless of registration order"
        );
    }

    // Scenario 2: 3 certifying witnesses (cert1, cert2, cert3)
    // All 6 permutations must produce identical AbsentWithCoverage (canonical selection).
    let mut cert3 = sample_coverage_witness(domain, true, true, false)?;
    cert3.negative_predicate = "no_perimeter_breach".to_string();

    let cert_witnesses = vec![cert1.clone(), cert2.clone(), cert3.clone()];
    let perms_cert = generate_permutations(&cert_witnesses);
    assert_eq!(perms_cert.len(), 6);

    let mut baseline_cert_witness: Option<CoverageWitness> = None;
    for (idx, perm) in perms_cert.iter().enumerate() {
        let mut store = EventRevisionStore::new(LedgerAnchor::genesis("site-coverage-perm-cert"));
        for (step, w) in perm.iter().enumerate() {
            store.register_coverage_witness(
                store.current_anchor().clone(),
                w.clone(),
                TimestampNs(1_000 + (step as i128) * 100),
            )?;
        }
        let result = store.read_event_in_domain(&absent_id, domain, None)?;
        let witness_clone = match result {
            EventReadResult::AbsentWithCoverage(w) => {
                assert!(w.certifies_absence());
                w.clone()
            }
            other => return Err(format!("expected AbsentWithCoverage, got {other:?}").into()),
        };
        if let Some(ref baseline) = baseline_cert_witness {
            assert_eq!(
                &witness_clone, baseline,
                "permutation {idx} must yield identical certifying witness"
            );
        } else {
            baseline_cert_witness = Some(witness_clone);
        }
    }

    // Scenario 3: Precedence test with 3 witnesses (certifying, uncertified, generation mismatch)
    // No gap, no exclusion: GenerationMismatch has precedence over CoverageWitnessUncertified.
    let mut gen_mismatch = sample_coverage_witness(domain, true, true, false)?;
    gen_mismatch.authorized_generation = 2;
    gen_mismatch.observed_generation = 1;

    let prec_witnesses = vec![cert1, uncert, gen_mismatch];
    let perms_prec = generate_permutations(&prec_witnesses);
    assert_eq!(perms_prec.len(), 6);

    let expected_gen_mismatch = EventReadResult::NotObservable {
        domain: domain.to_string(),
        reason: NotObservableReason::GenerationMismatch {
            expected: 2,
            observed: 1,
        },
        all_reasons: vec![
            NotObservableReason::GenerationMismatch {
                expected: 2,
                observed: 1,
            },
            NotObservableReason::CoverageWitnessUncertified,
        ],
    };

    for (idx, perm) in perms_prec.iter().enumerate() {
        let mut store = EventRevisionStore::new(LedgerAnchor::genesis("site-coverage-perm-prec"));
        for (step, w) in perm.iter().enumerate() {
            store.register_coverage_witness(
                store.current_anchor().clone(),
                w.clone(),
                TimestampNs(1_000 + (step as i128) * 100),
            )?;
        }
        let result = store.read_event_in_domain(&absent_id, domain, None)?;
        assert_eq!(
            result, expected_gen_mismatch,
            "permutation {idx} must yield GenerationMismatch by order-independent precedence"
        );
    }

    Ok(())
}

#[test]
fn coverage_for_absence_two_witnesses_certifying_plus_uncertified_gives_uncertified() -> TestResult
{
    let domain = "domain.cert_plus_uncert";
    let absent_id = EventId::parse("evt_absent_uncert")?;

    let cert = sample_coverage_witness(domain, true, true, false)?;
    let uncert = sample_coverage_witness(domain, true, false, false)?;

    // Registration order 1: cert then uncert
    let mut store1 = EventRevisionStore::new(LedgerAnchor::genesis("site-cert-uncert-1"));
    store1.register_coverage_witness(
        store1.current_anchor().clone(),
        cert.clone(),
        TimestampNs(1_000),
    )?;
    store1.register_coverage_witness(
        store1.current_anchor().clone(),
        uncert.clone(),
        TimestampNs(2_000),
    )?;

    let result1 = store1.read_event_in_domain(&absent_id, domain, None)?;
    assert_eq!(
        result1,
        EventReadResult::NotObservable {
            domain: domain.to_string(),
            reason: NotObservableReason::CoverageWitnessUncertified,
            all_reasons: vec![NotObservableReason::CoverageWitnessUncertified],
        }
    );

    // Registration order 2: uncert then cert
    let mut store2 = EventRevisionStore::new(LedgerAnchor::genesis("site-cert-uncert-2"));
    store2.register_coverage_witness(
        store2.current_anchor().clone(),
        uncert,
        TimestampNs(1_000),
    )?;
    store2.register_coverage_witness(store2.current_anchor().clone(), cert, TimestampNs(2_000))?;

    let result2 = store2.read_event_in_domain(&absent_id, domain, None)?;
    assert_eq!(
        result2,
        EventReadResult::NotObservable {
            domain: domain.to_string(),
            reason: NotObservableReason::CoverageWitnessUncertified,
            all_reasons: vec![NotObservableReason::CoverageWitnessUncertified],
        }
    );

    Ok(())
}

#[test]
fn coverage_for_absence_two_witnesses_certifying_plus_excluded_gives_excluded() -> TestResult {
    let domain = "domain.cert_plus_excluded";
    let absent_id = EventId::parse("evt_absent_excluded")?;

    let cert = sample_coverage_witness(domain, true, true, false)?;
    let excluded = sample_coverage_witness(domain, true, true, true)?;

    let expected_excluded = NotObservableReason::ExcludedDomain {
        domain: domain.to_string(),
    };

    // Registration order 1: cert then excluded
    let mut store1 = EventRevisionStore::new(LedgerAnchor::genesis("site-cert-excl-1"));
    store1.register_coverage_witness(
        store1.current_anchor().clone(),
        cert.clone(),
        TimestampNs(1_000),
    )?;
    store1.register_coverage_witness(
        store1.current_anchor().clone(),
        excluded.clone(),
        TimestampNs(2_000),
    )?;

    let result1 = store1.read_event_in_domain(&absent_id, domain, None)?;
    assert_eq!(
        result1,
        EventReadResult::NotObservable {
            domain: domain.to_string(),
            reason: expected_excluded.clone(),
            all_reasons: vec![expected_excluded.clone()],
        }
    );

    // Registration order 2: excluded then cert
    let mut store2 = EventRevisionStore::new(LedgerAnchor::genesis("site-cert-excl-2"));
    store2.register_coverage_witness(
        store2.current_anchor().clone(),
        excluded,
        TimestampNs(1_000),
    )?;
    store2.register_coverage_witness(store2.current_anchor().clone(), cert, TimestampNs(2_000))?;

    let result2 = store2.read_event_in_domain(&absent_id, domain, None)?;
    assert_eq!(
        result2,
        EventReadResult::NotObservable {
            domain: domain.to_string(),
            reason: expected_excluded.clone(),
            all_reasons: vec![expected_excluded],
        }
    );

    Ok(())
}

#[test]
fn coverage_for_absence_two_witnesses_gapped_plus_excluded_precedence() -> TestResult {
    let domain = "domain.gapped_plus_excluded";
    let absent_id = EventId::parse("evt_gapped_excl")?;

    let gapped = sample_coverage_witness(domain, false, true, false)?;
    let excluded = sample_coverage_witness(domain, true, true, true)?;

    let expected_all_reasons = vec![
        NotObservableReason::CoverageWitnessGapped,
        NotObservableReason::ExcludedDomain {
            domain: domain.to_string(),
        },
    ];

    // Registration order 1: gapped then excluded
    let mut store1 = EventRevisionStore::new(LedgerAnchor::genesis("site-gap-excl-1"));
    store1.register_coverage_witness(
        store1.current_anchor().clone(),
        gapped.clone(),
        TimestampNs(1_000),
    )?;
    store1.register_coverage_witness(
        store1.current_anchor().clone(),
        excluded.clone(),
        TimestampNs(2_000),
    )?;

    let result1 = store1.read_event_in_domain(&absent_id, domain, None)?;
    assert_eq!(
        result1,
        EventReadResult::NotObservable {
            domain: domain.to_string(),
            reason: NotObservableReason::CoverageWitnessGapped,
            all_reasons: expected_all_reasons.clone(),
        }
    );

    // Registration order 2: excluded then gapped
    let mut store2 = EventRevisionStore::new(LedgerAnchor::genesis("site-gap-excl-2"));
    store2.register_coverage_witness(
        store2.current_anchor().clone(),
        excluded,
        TimestampNs(1_000),
    )?;
    store2.register_coverage_witness(
        store2.current_anchor().clone(),
        gapped,
        TimestampNs(2_000),
    )?;

    let result2 = store2.read_event_in_domain(&absent_id, domain, None)?;
    assert_eq!(
        result2,
        EventReadResult::NotObservable {
            domain: domain.to_string(),
            reason: NotObservableReason::CoverageWitnessGapped,
            all_reasons: expected_all_reasons,
        }
    );

    Ok(())
}

#[test]
fn coverage_witness_capacity_exceeded_refusal_fails_closed() -> TestResult {
    let mut store = EventRevisionStore::new(LedgerAnchor::genesis("site-cap-refusal"));
    let domain = "domain.capacity_test";
    let absent_id = EventId::parse("evt_absent_cap")?;

    // Fill store to capacity (1024) with certifying witnesses.
    for i in 0..MAX_STORE_COVERAGE_WITNESSES {
        let mut witness = sample_coverage_witness(domain, true, true, false)?;
        witness.negative_predicate = format!("no_unauthorized_intrusion_{i:04}");
        store.register_coverage_witness(
            store.current_anchor().clone(),
            witness,
            TimestampNs(1_000 + (i as i128)),
        )?;
    }
    // Capacity is a pure function of the admitted witnesses; no refusal has happened yet.
    assert!(store.coverage_registry_at_capacity());
    let anchor_at_capacity = store.current_anchor().clone();

    // 1025th witness: a gapped witness for the same domain
    let gapped = sample_coverage_witness(domain, false, true, false)?;
    let refusal = store.register_coverage_witness(
        store.current_anchor().clone(),
        gapped,
        TimestampNs(100_000),
    );
    assert_eq!(
        refusal.err(),
        Some(EventStoreError::CoverageWitnessCapacityExceeded {
            limit: MAX_STORE_COVERAGE_WITNESSES,
            actual: MAX_STORE_COVERAGE_WITNESSES + 1,
        })
    );

    // The refusal leaves canonical history untouched: nothing outside history records it.
    assert_eq!(store.current_anchor(), &anchor_at_capacity);
    assert_eq!(store.commit_count(), MAX_STORE_COVERAGE_WITNESSES);

    // Absence read MUST NOT certify absence (fail-closed)
    let result = store.read_event_in_domain(&absent_id, domain, None)?;
    assert!(
        !matches!(result, EventReadResult::AbsentWithCoverage(_)),
        "capacity-refused domain must never certify absence"
    );

    match result {
        EventReadResult::NotObservable {
            domain: reported_domain,
            reason,
            all_reasons,
        } => {
            assert_eq!(reported_domain, domain);
            assert_eq!(
                reason,
                NotObservableReason::CoverageRegistryCapacityExceeded
            );
            assert!(all_reasons.contains(&NotObservableReason::CoverageRegistryCapacityExceeded));
            assert_eq!(
                all_reasons,
                vec![NotObservableReason::CoverageRegistryCapacityExceeded]
            );
        }
        other => return Err(format!("expected NotObservable, got {other:?}").into()),
    }

    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Criterion: global fail-closed coverage capacity derived from canonical history (fss-3qlsa)
// ---------------------------------------------------------------------------------------------

const CAPACITY_SITE: &str = "site-coverage-capacity";

/// A certifying witness for `domain` whose predicate is made unique by `index`.
fn certifying_witness(domain: &str, index: usize) -> Result<CoverageWitness, Box<dyn Error>> {
    let mut witness = sample_coverage_witness(domain, true, true, false)?;
    witness.negative_predicate = format!("no_unauthorized_intrusion_{index:05}");
    Ok(witness)
}

/// Registers `count` witnesses; witness `i` is built by `witness_for(i)`.
fn register_witnesses(
    store: &mut EventRevisionStore,
    count: usize,
    witness_for: impl Fn(usize) -> Result<CoverageWitness, Box<dyn Error>>,
) -> TestResult {
    for i in 0..count {
        store.register_coverage_witness(
            store.current_anchor().clone(),
            witness_for(i)?,
            TimestampNs(1_000 + (i as i128)),
        )?;
    }
    Ok(())
}

/// Witness 0 certifies `domain.x`, witness 1 is gapped for `domain.b_gapped`, and every other
/// witness certifies its own filler domain.
fn capacity_fixture_witness(i: usize) -> Result<CoverageWitness, Box<dyn Error>> {
    match i {
        0 => certifying_witness("domain.x", i),
        1 => sample_coverage_witness("domain.b_gapped", false, true, false),
        _ => certifying_witness(&format!("domain.fill_{i:04}"), i),
    }
}

/// Asserts the exact fail-closed capacity result on the event, lineage and graph read paths.
fn assert_capacity_fail_closed(
    store: &EventRevisionStore,
    domain: &str,
    expected_all: &[NotObservableReason],
) -> TestResult {
    let absent_id = EventId::parse("evt_capacity_absent")?;
    let reason = NotObservableReason::CoverageRegistryCapacityExceeded;
    assert_eq!(
        store.read_event_in_domain(&absent_id, domain, None)?,
        EventReadResult::NotObservable {
            domain: domain.to_string(),
            reason: reason.clone(),
            all_reasons: expected_all.to_vec(),
        },
        "event read for {domain}"
    );
    assert_eq!(
        store.read_lineage_in_domain(&absent_id, domain)?,
        LineageReadResult::NotObservable {
            domain: domain.to_string(),
            reason: reason.clone(),
            all_reasons: expected_all.to_vec(),
        },
        "lineage read for {domain}"
    );
    assert_eq!(
        store.read_evidence_graph("graph_capacity_absent", domain)?,
        GraphReadResult::NotObservable {
            domain: domain.to_string(),
            reason,
            all_reasons: expected_all.to_vec(),
        },
        "graph read for {domain}"
    );
    assert_eq!(
        store.coverage_non_observability_reasons(domain),
        expected_all.to_vec(),
        "reasons for {domain}"
    );
    Ok(())
}

/// Asserts that `domain` certifies absence from exactly `expected` on all three read paths.
fn assert_certified_absent(
    store: &EventRevisionStore,
    domain: &str,
    expected: &CoverageWitness,
) -> TestResult {
    let absent_id = EventId::parse("evt_capacity_absent")?;
    assert_eq!(
        store.read_event_in_domain(&absent_id, domain, None)?,
        EventReadResult::AbsentWithCoverage(expected)
    );
    assert_eq!(
        store.read_lineage_in_domain(&absent_id, domain)?,
        LineageReadResult::AbsentWithCoverage(expected)
    );
    assert_eq!(
        store.read_evidence_graph("graph_capacity_absent", domain)?,
        GraphReadResult::AbsentWithCoverage(expected)
    );
    assert_eq!(store.coverage_non_observability_reasons(domain), Vec::new());
    Ok(())
}

fn capacity_refusal() -> EventStoreError {
    EventStoreError::CoverageWitnessCapacityExceeded {
        limit: MAX_STORE_COVERAGE_WITNESSES,
        actual: MAX_STORE_COVERAGE_WITNESSES + 1,
    }
}

/// r3q2 probe p5: one refused witness naming 1024 domains, then a refused gapped witness for X.
/// Round 2 saturated its refused-domain table here and certified X absent from the older witness.
#[test]
fn coverage_capacity_one_refusal_naming_1024_domains_then_gapped_x_never_certifies() -> TestResult {
    let mut store = EventRevisionStore::new(LedgerAnchor::genesis(CAPACITY_SITE));
    register_witnesses(
        &mut store,
        MAX_STORE_COVERAGE_WITNESSES,
        capacity_fixture_witness,
    )?;
    let anchor_at_capacity = store.current_anchor().clone();

    let mut big = sample_coverage_witness("domain.junk_0000", true, true, false)?;
    for j in 1..MAX_STORE_COVERAGE_WITNESSES {
        big.observed_domain.insert(format!("domain.junk_{j:04}"));
        big.authorized_domain.insert(format!("domain.junk_{j:04}"));
    }
    assert_eq!(big.observed_domain.len(), MAX_STORE_COVERAGE_WITNESSES);
    let big_refusal = expect_err(store.register_coverage_witness(
        store.current_anchor().clone(),
        big,
        TimestampNs(50_000),
    ))?;
    assert_eq!(big_refusal, capacity_refusal());

    let gapped_x = sample_coverage_witness("domain.x", false, true, false)?;
    let x_refusal = expect_err(store.register_coverage_witness(
        store.current_anchor().clone(),
        gapped_x,
        TimestampNs(50_001),
    ))?;
    assert_eq!(x_refusal, capacity_refusal());
    assert_eq!(store.current_anchor(), &anchor_at_capacity);

    let cap = NotObservableReason::CoverageRegistryCapacityExceeded;
    assert_capacity_fail_closed(&store, "domain.x", std::slice::from_ref(&cap))?;
    assert_capacity_fail_closed(
        &store,
        "domain.junk_0007",
        &[cap.clone(), NotObservableReason::NoCoverageWitness],
    )?;
    assert_capacity_fail_closed(&store, "domain.fill_0002", std::slice::from_ref(&cap))?;
    Ok(())
}

/// r3q2 probe p6: 1024 single-domain refusals, then a refused gapped witness for X.
#[test]
fn coverage_capacity_1024_single_domain_refusals_then_gapped_x_never_certifies() -> TestResult {
    let mut store = EventRevisionStore::new(LedgerAnchor::genesis(CAPACITY_SITE));
    register_witnesses(
        &mut store,
        MAX_STORE_COVERAGE_WITNESSES,
        capacity_fixture_witness,
    )?;
    let anchor_at_capacity = store.current_anchor().clone();

    for j in 0..MAX_STORE_COVERAGE_WITNESSES {
        let late = certifying_witness(&format!("domain.late_{j:04}"), j)?;
        let refusal = expect_err(store.register_coverage_witness(
            store.current_anchor().clone(),
            late,
            TimestampNs(60_000 + (j as i128)),
        ))?;
        assert_eq!(refusal, capacity_refusal());
    }

    let gapped_x = sample_coverage_witness("domain.x", false, true, false)?;
    let x_refusal = expect_err(store.register_coverage_witness(
        store.current_anchor().clone(),
        gapped_x,
        TimestampNs(70_000),
    ))?;
    assert_eq!(x_refusal, capacity_refusal());
    assert_eq!(store.current_anchor(), &anchor_at_capacity);
    assert_eq!(store.commit_count(), MAX_STORE_COVERAGE_WITNESSES);

    let cap = NotObservableReason::CoverageRegistryCapacityExceeded;
    assert_capacity_fail_closed(&store, "domain.x", std::slice::from_ref(&cap))?;
    assert_capacity_fail_closed(
        &store,
        "domain.late_0000",
        &[cap, NotObservableReason::NoCoverageWitness],
    )?;
    Ok(())
}

/// At capacity every domain fails closed, whether or not a witness naming it was ever refused:
/// A had a refused gapped witness, B was never refused (and carries an admitted gap), C was
/// never seen, and a certified filler domain was never refused either.
#[test]
fn coverage_capacity_fails_closed_for_every_domain_on_event_lineage_and_graph_reads() -> TestResult
{
    let mut store = EventRevisionStore::new(LedgerAnchor::genesis(CAPACITY_SITE));
    register_witnesses(
        &mut store,
        MAX_STORE_COVERAGE_WITNESSES,
        capacity_fixture_witness,
    )?;
    assert!(store.coverage_registry_at_capacity());

    // The stale-basis check precedes the capacity check.
    let stale = expect_err(store.register_coverage_witness(
        LedgerAnchor::genesis("site-wrong-basis"),
        sample_coverage_witness("domain.x", false, true, false)?,
        TimestampNs(80_000),
    ))?;
    assert!(
        matches!(stale, EventStoreError::StaleAnchor { .. }),
        "stale basis must be reported before capacity, got {stale:?}"
    );

    let refusal = expect_err(store.register_coverage_witness(
        store.current_anchor().clone(),
        sample_coverage_witness("domain.x", false, true, false)?,
        TimestampNs(80_001),
    ))?;
    assert_eq!(refusal, capacity_refusal());

    let cap = NotObservableReason::CoverageRegistryCapacityExceeded;
    // A: certified by witness 0, then a gapped witness was refused.
    assert_capacity_fail_closed(&store, "domain.x", std::slice::from_ref(&cap))?;
    // B: never refused; its admitted gap is still reported, after the capacity reason.
    assert_capacity_fail_closed(
        &store,
        "domain.b_gapped",
        &[cap.clone(), NotObservableReason::CoverageWitnessGapped],
    )?;
    // C: never seen.
    assert_capacity_fail_closed(
        &store,
        "domain.c_never_seen",
        &[cap.clone(), NotObservableReason::NoCoverageWitness],
    )?;
    // A certified filler domain that no refused witness named.
    assert_capacity_fail_closed(&store, "domain.fill_0512", std::slice::from_ref(&cap))?;

    // The reserved unknown domain names nothing any witness could cover.
    assert_eq!(
        store.coverage_non_observability_reasons("unknown"),
        vec![NotObservableReason::UnknownDomain]
    );
    Ok(())
}

/// INV-015: capacity is derived from canonical history, so the rebuilt store equals the live
/// store and evaluates every domain identically, including after capacity refusals.
#[test]
fn coverage_capacity_rebuild_from_history_is_exact() -> TestResult {
    let genesis = LedgerAnchor::genesis(CAPACITY_SITE);
    let mut store = EventRevisionStore::new(genesis.clone());
    register_witnesses(
        &mut store,
        MAX_STORE_COVERAGE_WITNESSES,
        capacity_fixture_witness,
    )?;
    for (step, domain) in ["domain.x", "domain.c_never_seen", "domain.fill_0003"]
        .iter()
        .enumerate()
    {
        let refusal = expect_err(store.register_coverage_witness(
            store.current_anchor().clone(),
            sample_coverage_witness(domain, false, true, false)?,
            TimestampNs(90_000 + (step as i128)),
        ))?;
        assert_eq!(refusal, capacity_refusal());
    }

    let rebuilt = EventRevisionStore::rebuild_from_history(genesis.clone(), store.history())?;
    assert_eq!(rebuilt, store);
    assert_eq!(rebuilt.current_anchor(), store.current_anchor());
    assert_eq!(
        rebuilt.current_anchor().state_root,
        store.current_anchor().state_root
    );
    assert!(rebuilt.coverage_registry_at_capacity());
    assert_eq!(
        rebuilt.coverage_registry_at_capacity(),
        store.coverage_registry_at_capacity()
    );

    let absent_id = EventId::parse("evt_capacity_absent")?;
    let mut domains: Vec<String> = (2..MAX_STORE_COVERAGE_WITNESSES)
        .map(|i| format!("domain.fill_{i:04}"))
        .collect();
    domains.extend(
        [
            "domain.x",
            "domain.b_gapped",
            "domain.c_never_seen",
            "unknown",
            "",
        ]
        .iter()
        .map(|d| (*d).to_string()),
    );
    for domain in &domains {
        assert_eq!(
            rebuilt.read_event_in_domain(&absent_id, domain, None)?,
            store.read_event_in_domain(&absent_id, domain, None)?,
            "event read for {domain}"
        );
        assert_eq!(
            rebuilt.read_lineage_in_domain(&absent_id, domain)?,
            store.read_lineage_in_domain(&absent_id, domain)?,
            "lineage read for {domain}"
        );
        assert_eq!(
            rebuilt.read_evidence_graph("graph_capacity_absent", domain)?,
            store.read_evidence_graph("graph_capacity_absent", domain)?,
            "graph read for {domain}"
        );
        assert_eq!(
            rebuilt.coverage_non_observability_reasons(domain),
            store.coverage_non_observability_reasons(domain),
            "reasons for {domain}"
        );
    }
    assert_capacity_fail_closed(
        &rebuilt,
        "domain.x",
        &[NotObservableReason::CoverageRegistryCapacityExceeded],
    )?;

    // Rebuilding one commit short of capacity certifies again, exactly as the live store did.
    let short_history = store
        .history()
        .get(..MAX_STORE_COVERAGE_WITNESSES - 1)
        .ok_or("history must hold at least N-1 commits")?;
    let prefix = EventRevisionStore::rebuild_from_history(genesis, short_history)?;
    assert!(!prefix.coverage_registry_at_capacity());
    let witness_x = capacity_fixture_witness(0)?;
    assert_certified_absent(&prefix, "domain.x", &witness_x)?;
    Ok(())
}

/// Control at the boundary: with N-1 witnesses one certifying witness still certifies absence;
/// admitting the N-th witness puts the store at capacity and every domain fails closed.
#[test]
fn coverage_capacity_boundary_n_minus_one_certifies_and_n_fails_closed() -> TestResult {
    let mut store = EventRevisionStore::new(LedgerAnchor::genesis(CAPACITY_SITE));
    register_witnesses(
        &mut store,
        MAX_STORE_COVERAGE_WITNESSES - 1,
        capacity_fixture_witness,
    )?;
    assert!(!store.coverage_registry_at_capacity());
    let witness_x = capacity_fixture_witness(0)?;
    assert_certified_absent(&store, "domain.x", &witness_x)?;
    let witness_fill = capacity_fixture_witness(700)?;
    assert_certified_absent(&store, "domain.fill_0700", &witness_fill)?;
    assert_eq!(
        store.coverage_non_observability_reasons("domain.c_never_seen"),
        vec![NotObservableReason::NoCoverageWitness]
    );

    // The N-th witness is admitted.
    store.register_coverage_witness(
        store.current_anchor().clone(),
        certifying_witness("domain.last_admitted", MAX_STORE_COVERAGE_WITNESSES - 1)?,
        TimestampNs(95_000),
    )?;
    assert!(store.coverage_registry_at_capacity());
    assert_eq!(store.commit_count(), MAX_STORE_COVERAGE_WITNESSES);
    let cap = NotObservableReason::CoverageRegistryCapacityExceeded;
    assert_capacity_fail_closed(&store, "domain.x", std::slice::from_ref(&cap))?;
    assert_capacity_fail_closed(&store, "domain.last_admitted", std::slice::from_ref(&cap))?;
    assert_capacity_fail_closed(
        &store,
        "domain.c_never_seen",
        &[cap, NotObservableReason::NoCoverageWitness],
    )?;

    // The (N+1)-th is refused with the typed error.
    let refusal = expect_err(store.register_coverage_witness(
        store.current_anchor().clone(),
        certifying_witness("domain.x", MAX_STORE_COVERAGE_WITNESSES)?,
        TimestampNs(95_001),
    ))?;
    assert_eq!(refusal, capacity_refusal());
    Ok(())
}

/// Fills a store's history with genesis revisions and contradictions (no coverage witnesses).
struct CommitFill {
    contradiction: Contradiction,
    current_event: Option<EventId>,
    per_event: usize,
    event_index: usize,
    tick: i128,
}

impl CommitFill {
    fn fill_to(&mut self, store: &mut EventRevisionStore, target: usize) -> TestResult {
        while store.commit_count() < target {
            self.tick += 1;
            match self.current_event.clone() {
                Some(event_id) if self.per_event < MAX_CONTRADICTIONS_PER_EVENT => {
                    store.record_contradiction(
                        store.current_anchor().clone(),
                        event_id,
                        self.contradiction.clone(),
                        TimestampNs(self.tick),
                    )?;
                    self.per_event += 1;
                }
                _ => {
                    let genesis_rev =
                        sample_genesis(&format!("evt_commit_cap_{:05}", self.event_index))?;
                    let event_id = genesis_rev.event_id.clone();
                    store.append_genesis(
                        store.current_anchor().clone(),
                        genesis_rev,
                        "domain.commit_cap_events",
                        TimestampNs(self.tick),
                    )?;
                    self.current_event = Some(event_id);
                    self.per_event = 0;
                    self.event_index += 1;
                }
            }
        }
        Ok(())
    }
}

/// The commit-capacity branch: with only two witnesses admitted (far below the witness bound),
/// a full commit history refuses every later witness, so every domain fails closed.
#[test]
fn coverage_commit_capacity_refuses_witness_and_fails_closed_for_every_domain() -> TestResult {
    let genesis = LedgerAnchor::genesis("site-commit-capacity");
    let mut store = EventRevisionStore::new(genesis);
    let witness_x = certifying_witness("domain.x", 0)?;
    store.register_coverage_witness(
        store.current_anchor().clone(),
        witness_x.clone(),
        TimestampNs(1),
    )?;
    store.register_coverage_witness(
        store.current_anchor().clone(),
        sample_coverage_witness("domain.b_gapped", false, true, false)?,
        TimestampNs(2),
    )?;

    let mut fill = CommitFill {
        contradiction: sample_contradiction(
            "contra_commit_cap",
            "claim_commit_cap",
            &["world.commit_cap"],
        )?,
        current_event: None,
        per_event: 0,
        event_index: 0,
        tick: 10,
    };

    // One commit below the commit bound: still below capacity, X still certifies.
    fill.fill_to(&mut store, MAX_STORE_COMMITS - 1)?;
    assert!(!store.coverage_registry_at_capacity());
    assert_certified_absent(&store, "domain.x", &witness_x)?;

    fill.fill_to(&mut store, MAX_STORE_COMMITS)?;
    let tick = fill.tick;
    assert_eq!(store.commit_count(), MAX_STORE_COMMITS);
    assert!(store.coverage_registry_at_capacity());
    let anchor_at_capacity = store.current_anchor().clone();

    // The stale-basis check still comes first.
    let stale = expect_err(store.register_coverage_witness(
        LedgerAnchor::genesis("site-wrong-basis"),
        sample_coverage_witness("domain.x", false, true, false)?,
        TimestampNs(tick + 1),
    ))?;
    assert!(
        matches!(stale, EventStoreError::StaleAnchor { .. }),
        "stale basis must be reported before capacity, got {stale:?}"
    );

    // A gapped witness for X is refused by the commit-capacity branch, not the witness bound.
    let refusal = expect_err(store.register_coverage_witness(
        store.current_anchor().clone(),
        sample_coverage_witness("domain.x", false, true, false)?,
        TimestampNs(tick + 2),
    ))?;
    assert_eq!(
        refusal,
        EventStoreError::StoreCommitCapacityExceeded {
            limit: MAX_STORE_COMMITS,
            actual: MAX_STORE_COMMITS + 1,
        }
    );
    assert_eq!(store.current_anchor(), &anchor_at_capacity);

    let cap = NotObservableReason::CoverageRegistryCapacityExceeded;
    assert_capacity_fail_closed(&store, "domain.x", std::slice::from_ref(&cap))?;
    assert_capacity_fail_closed(
        &store,
        "domain.b_gapped",
        &[cap.clone(), NotObservableReason::CoverageWitnessGapped],
    )?;
    assert_capacity_fail_closed(
        &store,
        "domain.c_never_seen",
        &[cap, NotObservableReason::NoCoverageWitness],
    )?;
    Ok(())
}

/// Tie-break: with several certifying witnesses on one domain, the certifying witness returned is
/// exactly the one with the lowest witness digest, whatever the registration order. The witnesses
/// are registered so that the lowest-digest one is neither first nor last.
#[test]
fn coverage_for_absence_multiple_certifying_witnesses_returns_lowest_digest() -> TestResult {
    let domain = "domain.tie_break";
    let mut witnesses = vec![
        certifying_witness(domain, 1)?,
        certifying_witness(domain, 2)?,
        certifying_witness(domain, 3)?,
    ];
    witnesses.sort_by_key(CoverageWitness::witness_digest);
    let [lowest, middle, highest] = witnesses.as_slice() else {
        return Err("expected exactly three witnesses".into());
    };
    assert!(lowest.witness_digest() < middle.witness_digest());
    assert!(middle.witness_digest() < highest.witness_digest());

    for order in [[middle, lowest, highest], [highest, lowest, middle]] {
        let mut store = EventRevisionStore::new(LedgerAnchor::genesis("site-tie-break"));
        for (step, witness) in order.iter().enumerate() {
            store.register_coverage_witness(
                store.current_anchor().clone(),
                (*witness).clone(),
                TimestampNs(1_000 + (step as i128)),
            )?;
        }
        assert_certified_absent(&store, domain, lowest)?;
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------
// Criterion: coverage-registry rotation resumes certification, keeps refused domains blocked,
// and rebuilds identically (fss-qlaao)
// ------------------------------------------------------------------------------------------

#[test]
fn coverage_rotation_resumes_certification_and_refused_domains_stay_blocked() -> TestResult {
    let mut store = EventRevisionStore::new(LedgerAnchor::genesis("site-cap-rotation"));
    let blocked = "domain.rotation_refused";
    let sealed = "domain.rotation_sealed";
    let fresh = "domain.rotation_fresh";

    // Fill the registry to capacity: 1023 certifying witnesses for `blocked`, one for `sealed`.
    for i in 0..MAX_STORE_COVERAGE_WITNESSES {
        let domain = if i == 0 { sealed } else { blocked };
        let mut witness = sample_coverage_witness(domain, true, true, false)?;
        witness.negative_predicate = format!("no_unauthorized_intrusion_{i:04}");
        store.register_coverage_witness(
            store.current_anchor().clone(),
            witness,
            TimestampNs(1_000 + i as i128),
        )?;
    }
    assert!(store.coverage_registry_at_capacity());

    // The 1025th witness (a gapped report for `blocked`) is refused at capacity.
    let refused_witness = sample_coverage_witness(blocked, false, true, false)?;
    assert!(store
        .register_coverage_witness(
            store.current_anchor().clone(),
            refused_witness.clone(),
            TimestampNs(100_000),
        )
        .is_err());
    let anchor_at_capacity = store.current_anchor().clone();
    let refused_id = EventId::parse("evt_rotation_refused")?;
    match store.read_event_in_domain(&refused_id, blocked, None)? {
        EventReadResult::NotObservable { reason, .. } => {
            assert_eq!(reason, NotObservableReason::CoverageRegistryCapacityExceeded);
        }
        other => return Err(format!("expected NotObservable, got {other:?}").into()),
    }

    // Rotation: a canonical commit that seals the live registry and records the refused report.
    let rotation_digest = store.rotate_coverage_registry(
        store.current_anchor().clone(),
        vec![refused_witness.clone()],
        TimestampNs(200_000),
    )?;
    assert!(!store.coverage_registry_at_capacity());
    assert_eq!(store.rotated_refused(), &[refused_witness.clone()]);
    assert_ne!(store.current_anchor(), &anchor_at_capacity);

    // Post-rotation admission works again.
    let new_witness = sample_coverage_witness(fresh, true, true, false)?;
    store.register_coverage_witness(
        store.current_anchor().clone(),
        new_witness,
        TimestampNs(300_000),
    )?;

    // Absence is certifiable for a domain covered by a post-rotation witness.
    let fresh_id = EventId::parse("evt_rotation_fresh")?;
    match store.read_event_in_domain(&fresh_id, fresh, None)? {
        EventReadResult::AbsentWithCoverage(_) => {}
        other => return Err(format!("expected certified absence, got {other:?}").into()),
    }

    // The refused domain stays blocked even though the registry was rotated.
    match store.read_event_in_domain(&refused_id, blocked, None)? {
        EventReadResult::NotObservable { reason, .. } => {
            assert_eq!(reason, NotObservableReason::CoverageWitnessGapped);
        }
        other => return Err(format!("expected NotObservable, got {other:?}").into()),
    }

    // A sealed domain with no post-rotation witness is honestly unknown, never absence.
    let sealed_id = EventId::parse("evt_rotation_sealed")?;
    match store.read_event_in_domain(&sealed_id, sealed, None)? {
        EventReadResult::NotObservable { reason, .. } => {
            assert_eq!(reason, NotObservableReason::NoCoverageWitness);
        }
        other => return Err(format!("expected NotObservable, got {other:?}").into()),
    }

    // Rebuild equality: the replayed store reaches the identical state and verdicts.
    let rebuilt = EventRevisionStore::rebuild_from_history(
        LedgerAnchor::genesis("site-cap-rotation"),
        store.history(),
    )?;
    assert_eq!(rebuilt.commit_count(), store.commit_count());
    assert_eq!(
        rebuilt.coverage_registry_at_capacity(),
        store.coverage_registry_at_capacity()
    );
    assert_eq!(rebuilt.rotated_refused(), store.rotated_refused());
    assert_eq!(
        rebuilt.current_anchor(),
        store.current_anchor(),
        "rebuild anchor must match"
    );
    for (domain, expected) in [
        (blocked, NotObservableReason::CoverageWitnessGapped),
        (fresh, NotObservableReason::NoCoverageWitness),
    ] {
        // `fresh` has a certifying witness: re-check via the absence read instead.
        if domain == fresh {
            match rebuilt.read_event_in_domain(&fresh_id, fresh, None)? {
                EventReadResult::AbsentWithCoverage(_) => {}
                other => return Err(format!("rebuild expected absence, got {other:?}").into()),
            }
        } else {
            match rebuilt.read_event_in_domain(&refused_id, domain, None)? {
                EventReadResult::NotObservable { reason, .. } => {
                    assert_eq!(reason, expected);
                }
                other => return Err(format!("rebuild expected NotObservable, got {other:?}").into()),
            }
        }
    }

    // Mutant: a rotation commit whose sealed count disagrees with the live registry is
    // fail-closed during replay.
    let mut tampered_history = store.history().to_vec();
    let last = tampered_history.len() - 1;
    if let EventStoreEntry::RotateCoverageRegistry { sealed_count, .. } =
        &mut tampered_history[last].entry
    {
        *sealed_count += 1;
    } else {
        return Err("expected rotation commit at history tail".into());
    }
    let replay = EventRevisionStore::rebuild_from_history(
        LedgerAnchor::genesis("site-cap-rotation"),
        &tampered_history,
    );
    match replay {
        Err(EventStoreError::CommitDigestMismatch { sequence, .. }) => {
            assert_eq!(sequence, MAX_STORE_COVERAGE_WITNESSES as u64 + 1);
        }
        other => return Err(format!("expected CommitDigestMismatch, got {other:?}").into()),
    }

    // Canonical roundtrip of the rotation entry.
    let entry = EventStoreEntry::RotateCoverageRegistry {
        sealed_digest: rotation_digest,
        sealed_count: MAX_STORE_COVERAGE_WITNESSES as u64,
        refused: vec![refused_witness],
    };
    let bytes = {
        let mut encoder = CanonicalEncoder::new();
        entry.encode_canonical(&mut encoder);
        encoder.finish()
    };
    assert_eq!(
        EventStoreEntry::decode_canonical(&mut CanonicalDecoder::new(&bytes))?,
        entry
    );

    Ok(())
}
