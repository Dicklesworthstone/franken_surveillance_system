#![forbid(unsafe_code)]
//! Integration and contract tests verifying sensor tamper stickiness across revisions (fss-2uftm).
//!
//! A sensor tamper report must stay an open integrity risk until an explicit, evidenced
//! integrity-restoration event retires it; until then presence cannot be corroborated or
//! adjudicated, unretired tamper edges remain sticky in revision evidence, and planted-bypass
//! revisions omitting the tamper edge are refused.

use std::error::Error;

use fss_core::event::{
    EventLineage, EventSupersedeParams, EventTransitionError, EventTransitionParams,
    compute_sensor_tamper_status,
};
use fss_core::{
    CaptureInterval, ContentDigest, ContractError, DecisionPath, DigestAlgorithm,
    EVENT_HYPOTHESIS_SCHEMA, EventDecodeError, EventEvidence, EventHypothesis, EventId, EventKind,
    EventState, EvidenceClass, EvidenceEdgeRelation, ProbabilityInterval, TimestampNs,
};

fn sample_interval() -> Result<CaptureInterval, ContractError> {
    CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))
}

/// The `step`-th capture interval after [`sample_interval`], each one starting strictly after the
/// previous one ends. A restoration retires a tamper only when captured strictly after it.
fn later_interval(step: i128) -> Result<CaptureInterval, ContractError> {
    CaptureInterval::new(
        TimestampNs(1_000_000 + step * 2_000_000),
        TimestampNs(2_000_000 + step * 2_000_000),
    )
}

fn sample_decision_path(label: &str) -> DecisionPath {
    DecisionPath {
        policy_generation: ContentDigest::sha256(format!("policy:{label}").as_bytes()),
        fingerprint: ContentDigest::sha256(format!("fingerprint:{label}").as_bytes()),
        abstained: false,
        abstention_reason: None,
    }
}

fn sample_evidence(domain: &str, supports: bool) -> EventEvidence {
    let digest = ContentDigest::sha256(format!("evidence:{domain}:support:{supports}").as_bytes());
    EventEvidence {
        digest,
        class: EvidenceClass::Derived,
        failure_domain: domain.to_string(),
        supports,
        relation: if supports {
            EvidenceEdgeRelation::Supports
        } else {
            EvidenceEdgeRelation::Contradicts
        },
        capsule_digest: None,
        identity_digest: None,
    }
}

fn tamper_evidence(domain: &str) -> EventEvidence {
    let digest = ContentDigest::sha256(format!("evidence:{domain}:tamper").as_bytes());
    EventEvidence {
        digest,
        class: EvidenceClass::Derived,
        failure_domain: domain.to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorTamper,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(format!("sensor:{domain}").as_bytes())),
    }
}

fn restoration_evidence(domain: &str) -> EventEvidence {
    let digest = ContentDigest::sha256(format!("evidence:{domain}:restoration").as_bytes());
    EventEvidence {
        digest,
        class: EvidenceClass::Derived,
        failure_domain: domain.to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorIntegrityRestoration,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(format!("sensor:{domain}").as_bytes())),
    }
}

fn sample_genesis_hypothesis(
    event_id: &EventId,
    domain: &str,
    tampered: bool,
) -> Result<EventHypothesis, Box<dyn Error>> {
    let mut evidence = vec![sample_evidence(domain, true)];
    if tampered {
        evidence.push(tamper_evidence(domain));
    }
    let probability = ProbabilityInterval::new(0.8, 0.95)?;
    let event = EventHypothesis {
        schema: EVENT_HYPOTHESIS_SCHEMA.to_string(),
        event_id: event_id.clone(),
        revision: 1,
        supersedes: None,
        state: EventState::Hypothesized,
        kind: EventKind::UnknownPresence,
        interval: sample_interval()?,
        uncertainty_reason: None,
        zone_ids: vec!["zone-1".to_string()],
        track_ids: vec!["track-1".to_string()],
        probability,
        evidence,
        model_receipts: vec![ContentDigest::sha256(b"receipt-1")],
        decision_path: sample_decision_path("genesis"),
    };
    event.verify()?;
    Ok(event)
}

fn transition_params(
    target_state: EventState,
    interval: CaptureInterval,
    evidence: Vec<EventEvidence>,
) -> Result<EventTransitionParams, ContractError> {
    Ok(EventTransitionParams {
        target_state,
        kind: EventKind::UnknownPresence,
        interval,
        uncertainty_reason: None,
        zone_ids: vec!["zone-1".to_string()],
        track_ids: vec!["track-1".to_string()],
        probability: ProbabilityInterval::new(0.8, 0.95)?,
        evidence,
        model_receipts: vec![ContentDigest::sha256(b"receipt-1")],
        decision_path: sample_decision_path("transition"),
        urgent_single_sensor: false,
    })
}

#[test]
fn test_sensor_integrity_restoration_relation_properties() -> Result<(), Box<dyn Error>> {
    let rel = EvidenceEdgeRelation::SensorIntegrityRestoration;
    assert_eq!(rel as u8, 10);
    assert_eq!(rel.as_str(), "sensor_integrity_restoration");
    assert_eq!(
        EvidenceEdgeRelation::from_u8(10)?,
        EvidenceEdgeRelation::SensorIntegrityRestoration
    );
    assert_eq!(
        EvidenceEdgeRelation::parse("sensor_integrity_restoration")?,
        EvidenceEdgeRelation::SensorIntegrityRestoration
    );
    assert!(!rel.required_supports_flag());

    // reports_integrity_restoration returns true only for supports=false and SensorIntegrityRestoration
    let restoration = restoration_evidence("cam-1");
    assert!(restoration.reports_integrity_restoration());
    assert!(!restoration.reports_sensor_tamper());

    let tamper = tamper_evidence("cam-1");
    assert!(tamper.reports_sensor_tamper());
    assert!(!tamper.reports_integrity_restoration());

    // Supporting flag on SensorIntegrityRestoration is refused during verify
    let mut invalid = restoration_evidence("cam-1");
    invalid.supports = true;
    let event_id = EventId::parse("event:restoration:props")?;
    let probability = ProbabilityInterval::new(0.7, 0.9)?;
    let bad_event = EventHypothesis {
        schema: EVENT_HYPOTHESIS_SCHEMA.to_string(),
        event_id: event_id.clone(),
        revision: 1,
        supersedes: None,
        state: EventState::Witnessed,
        kind: EventKind::UnknownPresence,
        interval: sample_interval()?,
        uncertainty_reason: None,
        zone_ids: vec!["zone-1".to_string()],
        track_ids: vec!["track-1".to_string()],
        probability,
        evidence: vec![invalid],
        model_receipts: vec![ContentDigest::sha256(b"receipt")],
        decision_path: sample_decision_path("invalid-props"),
    };
    assert!(matches!(
        bad_event.verify(),
        Err(EventDecodeError::Contradiction {
            field: "evidence.supports",
            ..
        })
    ));

    // Neutral: cannot witness presence on its own
    let neutral_only = EventHypothesis {
        schema: EVENT_HYPOTHESIS_SCHEMA.to_string(),
        event_id,
        revision: 1,
        supersedes: None,
        state: EventState::Witnessed,
        kind: EventKind::UnknownPresence,
        interval: sample_interval()?,
        uncertainty_reason: None,
        zone_ids: vec!["zone-1".to_string()],
        track_ids: vec!["track-1".to_string()],
        probability,
        evidence: vec![restoration_evidence("cam-1")],
        model_receipts: vec![ContentDigest::sha256(b"receipt")],
        decision_path: sample_decision_path("neutral-only"),
    };
    assert_eq!(
        neutral_only.validate(),
        Err(ContractError::SupportingEvidenceRequired)
    );

    Ok(())
}

#[test]
fn test_sensor_tamper_sticky_in_supersede_and_blocks_corroboration() -> Result<(), Box<dyn Error>> {
    let event_id = EventId::parse("event:tamper:supersede")?;
    let genesis = sample_genesis_hypothesis(&event_id, "cam-1", true)?;
    assert!(
        genesis
            .evidence
            .iter()
            .any(EventEvidence::reports_sensor_tamper)
    );

    // Advance to Witnessed omitting the tamper edge: the unretired tamper edge is sticky and retained
    let rev1 = genesis.supersede(
        EventSupersedeParams {
            state: EventState::Witnessed,
            kind: genesis.kind,
            interval: genesis.interval,
            uncertainty_reason: None,
            zone_ids: genesis.zone_ids.clone(),
            track_ids: genesis.track_ids.clone(),
            probability: genesis.probability,
            evidence: vec![sample_evidence("cam-1", true)],
            model_receipts: genesis.model_receipts.clone(),
            decision_path: genesis.decision_path.clone(),
        },
        std::slice::from_ref(&genesis),
    )?;
    assert!(
        rev1.evidence
            .iter()
            .any(EventEvidence::reports_sensor_tamper)
    );

    // Planted bypass attempt 1: supersede rev1 (Witnessed) to Corroborated with supporting
    // evidence from cam-1 and cam-2, deliberately omitting the tamper edge.
    let bypass_evidence = vec![
        sample_evidence("cam-1", true),
        sample_evidence("cam-2", true),
    ];
    let bypass_attempt = rev1.supersede(
        EventSupersedeParams {
            state: EventState::Corroborated,
            kind: rev1.kind,
            interval: rev1.interval,
            uncertainty_reason: None,
            zone_ids: rev1.zone_ids.clone(),
            track_ids: rev1.track_ids.clone(),
            probability: rev1.probability,
            evidence: bypass_evidence.clone(),
            model_receipts: rev1.model_receipts.clone(),
            decision_path: rev1.decision_path.clone(),
        },
        &[genesis.clone(), rev1.clone()],
    );
    assert_eq!(
        bypass_attempt,
        Err(EventDecodeError::Contract(
            ContractError::SensorIntegrityRisk
        ))
    );

    // Supersede rev1 to Indeterminate omitting the tamper edge: unretired tamper remains sticky
    let rev2 = rev1.supersede(
        EventSupersedeParams {
            state: EventState::Indeterminate,
            kind: rev1.kind,
            interval: rev1.interval,
            uncertainty_reason: Some("tamper-investigation".to_string()),
            zone_ids: rev1.zone_ids.clone(),
            track_ids: rev1.track_ids.clone(),
            probability: rev1.probability,
            evidence: vec![sample_evidence("cam-1", true)],
            model_receipts: rev1.model_receipts.clone(),
            decision_path: rev1.decision_path.clone(),
        },
        &[genesis.clone(), rev1.clone()],
    )?;
    assert!(
        rev2.evidence
            .iter()
            .any(EventEvidence::reports_sensor_tamper)
    );

    // Trying to supersede rev2 to Corroborated still fails
    let bypass_attempt_2 = rev2.supersede(
        EventSupersedeParams {
            state: EventState::Corroborated,
            kind: rev2.kind,
            interval: rev2.interval,
            uncertainty_reason: None,
            zone_ids: rev2.zone_ids.clone(),
            track_ids: rev2.track_ids.clone(),
            probability: rev2.probability,
            evidence: bypass_evidence,
            model_receipts: rev2.model_receipts.clone(),
            decision_path: rev2.decision_path.clone(),
        },
        &[genesis.clone(), rev1.clone(), rev2.clone()],
    );
    assert_eq!(
        bypass_attempt_2,
        Err(EventDecodeError::Contract(
            ContractError::SensorIntegrityRisk
        ))
    );

    Ok(())
}

#[test]
fn test_sensor_tamper_sticky_in_lineage_transition_and_append() -> Result<(), Box<dyn Error>> {
    let event_id = EventId::parse("event:tamper:lineage")?;
    let genesis = sample_genesis_hypothesis(&event_id, "cam-1", true)?;
    let mut lineage = EventLineage::new(genesis.clone())?;

    assert!(lineage.has_open_sensor_tamper());
    assert_eq!(
        lineage
            .open_sensor_tamper_domains()
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["cam-1".to_string()]
    );

    // Advance to Witnessed omitting the tamper edge: tamper is sticky and propagated into current revision
    let params_witness = transition_params(
        EventState::Witnessed,
        genesis.interval,
        vec![sample_evidence("cam-1", true)],
    )?;
    lineage.transition(params_witness)?;
    assert!(lineage.has_open_sensor_tamper());
    assert!(
        lineage
            .current()
            .evidence
            .iter()
            .any(EventEvidence::reports_sensor_tamper)
    );

    // Planted bypass attempt 1: transition to Corroborated omitting tamper edge
    let params_1 = transition_params(
        EventState::Corroborated,
        genesis.interval,
        vec![
            sample_evidence("cam-1", true),
            sample_evidence("cam-2", true),
        ],
    )?;
    let bypass_transition = lineage.transition(params_1);
    assert_eq!(
        bypass_transition,
        Err(EventTransitionError::SensorIntegrityRisk)
    );

    // Planted bypass attempt 2: replay / from_revisions with an artificially created
    // Corroborated revision omitting the tamper edge
    let prior_digest = lineage.current().revision_digest();
    let artificial_corroborated = EventHypothesis {
        schema: EVENT_HYPOTHESIS_SCHEMA.to_string(),
        event_id: event_id.clone(),
        revision: 3,
        supersedes: Some(prior_digest),
        kind: EventKind::UnknownPresence,
        interval: genesis.interval,
        state: EventState::Corroborated,
        uncertainty_reason: None,
        zone_ids: genesis.zone_ids.clone(),
        track_ids: genesis.track_ids.clone(),
        probability: genesis.probability,
        evidence: vec![
            sample_evidence("cam-1", true),
            sample_evidence("cam-2", true),
        ],
        model_receipts: genesis.model_receipts.clone(),
        decision_path: sample_decision_path("artificial-corroborated"),
    };
    let replay_err = EventLineage::from_revisions(vec![
        genesis.clone(),
        lineage.current().clone(),
        artificial_corroborated.clone(),
    ]);
    assert_eq!(replay_err, Err(EventTransitionError::SensorIntegrityRisk));

    // Planted bypass attempt 3: verify_chain rejects chain with Corroborated after unretired tamper
    let chain_err = EventHypothesis::verify_chain(&[
        genesis,
        lineage.current().clone(),
        artificial_corroborated,
    ]);
    assert_eq!(
        chain_err,
        Err(EventDecodeError::Contract(
            ContractError::SensorIntegrityRisk
        ))
    );

    Ok(())
}

#[test]
fn test_explicit_evidenced_restoration_retires_tamper() -> Result<(), Box<dyn Error>> {
    let event_id = EventId::parse("event:tamper:restored")?;
    let genesis = sample_genesis_hypothesis(&event_id, "cam-1", true)?;
    let mut lineage = EventLineage::new(genesis.clone())?;

    assert!(lineage.has_open_sensor_tamper());

    // Advance lineage with explicit integrity restoration evidence for cam-1
    let restoration = restoration_evidence("cam-1");
    let params_restore = transition_params(
        EventState::Witnessed,
        later_interval(1)?,
        vec![sample_evidence("cam-1", true), restoration.clone()],
    )?;
    let transition_res = lineage.transition(params_restore);
    assert!(transition_res.is_ok(), "{transition_res:?}");

    // Tamper is now retired
    assert!(!lineage.has_open_sensor_tamper());
    assert!(lineage.open_sensor_tamper_domains().is_empty());
    let status = lineage.sensor_tamper_status();
    assert_eq!(status.restorations.len(), 1);
    assert_eq!(status.restorations[0].0, "cam-1");

    // Now transition to Corroborated succeeds with independent failure domain support
    let params_corrob = transition_params(
        EventState::Corroborated,
        genesis.interval,
        vec![
            sample_evidence("cam-1", true),
            sample_evidence("cam-2", true),
        ],
    )?;
    let corroboration = lineage.transition(params_corrob);
    assert!(corroboration.is_ok(), "{corroboration:?}");
    assert_eq!(lineage.current_state(), EventState::Corroborated);

    Ok(())
}

#[test]
fn test_multi_domain_tamper_isolation() -> Result<(), Box<dyn Error>> {
    let event_id = EventId::parse("event:tamper:multi")?;
    let probability = ProbabilityInterval::new(0.8, 0.95)?;
    let genesis = EventHypothesis {
        schema: EVENT_HYPOTHESIS_SCHEMA.to_string(),
        event_id,
        revision: 1,
        supersedes: None,
        state: EventState::Hypothesized,
        kind: EventKind::UnknownPresence,
        interval: sample_interval()?,
        uncertainty_reason: None,
        zone_ids: vec!["zone-1".to_string()],
        track_ids: vec!["track-1".to_string()],
        probability,
        evidence: vec![
            sample_evidence("cam-1", true),
            tamper_evidence("cam-1"),
            sample_evidence("cam-2", true),
            tamper_evidence("cam-2"),
        ],
        model_receipts: vec![ContentDigest::sha256(b"receipt-1")],
        decision_path: sample_decision_path("multi-tamper"),
    };
    genesis.verify()?;

    let status = compute_sensor_tamper_status(std::iter::once(&genesis), None);
    assert!(status.has_open_tamper());
    assert_eq!(status.open_domains.len(), 2);
    assert!(status.open_domains.contains("cam-1"));
    assert!(status.open_domains.contains("cam-2"));
    assert_eq!(status.open_tamper_roots.len(), 2);

    let mut lineage = EventLineage::new(genesis.clone())?;

    // Restore cam-1 only
    let r1 = restoration_evidence("cam-1");
    let params_r1 = transition_params(
        EventState::Witnessed,
        later_interval(1)?,
        vec![sample_evidence("cam-1", true), r1],
    )?;
    let transition_1 = lineage.transition(params_r1);
    assert!(transition_1.is_ok());

    // cam-2 is still tampered, so open tamper persists
    assert!(lineage.has_open_sensor_tamper());
    assert_eq!(
        lineage
            .open_sensor_tamper_domains()
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["cam-2".to_string()]
    );
    let status_mid = lineage.sensor_tamper_status();
    assert_eq!(status_mid.open_tamper_roots.len(), 1);

    // Corroboration is still refused
    let params_premature = transition_params(
        EventState::Corroborated,
        genesis.interval,
        vec![
            sample_evidence("cam-1", true),
            sample_evidence("cam-3", true),
        ],
    )?;
    let premature_corroboration = lineage.transition(params_premature);
    assert_eq!(
        premature_corroboration,
        Err(EventTransitionError::SensorIntegrityRisk)
    );

    // Now restore cam-2 as well via Indeterminate reconciliation
    let r2 = restoration_evidence("cam-2");
    let params_r2 = transition_params(
        EventState::Indeterminate,
        later_interval(2)?,
        vec![sample_evidence("cam-2", true), r2],
    )?;
    let transition_2 = lineage.transition(params_r2);
    assert!(transition_2.is_ok());

    // All tamper risks retired
    assert!(!lineage.has_open_sensor_tamper());
    assert!(lineage.open_sensor_tamper_domains().is_empty());

    // Now corroboration succeeds
    let params_ok = transition_params(
        EventState::Corroborated,
        genesis.interval,
        vec![
            sample_evidence("cam-1", true),
            sample_evidence("cam-2", true),
        ],
    )?;
    let ok_corroboration = lineage.transition(params_ok);
    assert!(ok_corroboration.is_ok());

    Ok(())
}

#[test]
fn test_zero_digest_and_missing_identity_restoration_refused() -> Result<(), Box<dyn Error>> {
    let zero_edge = EventEvidence {
        digest: ContentDigest::new(DigestAlgorithm::Sha256, [0u8; 32]),
        class: EvidenceClass::Derived,
        failure_domain: "power:alpha".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorIntegrityRestoration,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor-1")),
    };
    assert_eq!(
        zero_edge.verify(),
        Err(EventDecodeError::Contract(ContractError::InvalidDigest))
    );
    assert!(!zero_edge.reports_integrity_restoration());

    let missing_id_edge = EventEvidence {
        digest: ContentDigest::sha256(b"valid-digest"),
        class: EvidenceClass::Derived,
        failure_domain: "power:alpha".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorIntegrityRestoration,
        capsule_digest: None,
        identity_digest: None,
    };
    assert_eq!(
        missing_id_edge.verify(),
        Err(EventDecodeError::Contract(ContractError::EvidenceRequired))
    );
    assert!(!missing_id_edge.reports_integrity_restoration());

    Ok(())
}

#[test]
fn test_same_batch_restoration_does_not_retire_tamper() -> Result<(), Box<dyn Error>> {
    let t = tamper_evidence("cam-1");
    let r = restoration_evidence("cam-1");
    let status = compute_sensor_tamper_status(std::iter::empty(), Some(&[t, r]));
    assert!(status.has_open_tamper());
    assert_eq!(status.open_domains.len(), 1);
    assert!(status.open_domains.contains("cam-1"));
    assert!(status.restorations.is_empty());
    Ok(())
}

#[test]
fn test_same_batch_restoration_refused() -> Result<(), Box<dyn Error>> {
    let event_id = EventId::parse("event:tamper:same-batch-restoration")?;
    let genesis = sample_genesis_hypothesis(&event_id, "cam-1", true)?;
    let mut lineage = EventLineage::new(genesis.clone())?;
    assert!(lineage.has_open_sensor_tamper());

    let t2 = EventEvidence {
        digest: ContentDigest::sha256(b"tamper-rev-2"),
        class: EvidenceClass::Derived,
        failure_domain: "cam-2".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorTamper,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:cam-2")),
    };
    let r2 = EventEvidence {
        digest: ContentDigest::sha256(b"restoration-rev-2"),
        class: EvidenceClass::Derived,
        failure_domain: "cam-2".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorIntegrityRestoration,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:cam-2")),
    };
    let params = transition_params(
        EventState::Witnessed,
        later_interval(1)?,
        vec![sample_evidence("cam-2", true), t2, r2],
    )?;
    let res = lineage.transition(params);
    assert!(res.is_ok());
    assert!(lineage.open_sensor_tamper_domains().contains("cam-2"));
    Ok(())
}

#[test]
fn test_time_stale_restoration_refused() -> Result<(), Box<dyn Error>> {
    let event_id = EventId::parse("event:tamper:time-stale-restoration")?;
    // Tamper captured at 5000000..7000100
    let tamper_interval = CaptureInterval::new(TimestampNs(5_000_000), TimestampNs(7_000_100))?;
    let t1 = EventEvidence {
        digest: ContentDigest::sha256(b"tamper-interval-1"),
        class: EvidenceClass::Derived,
        failure_domain: "cam-1".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorTamper,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:cam-1")),
    };
    let genesis = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_string(),
        event_id: event_id.clone(),
        revision: 1,
        supersedes: None,
        state: EventState::Hypothesized,
        kind: EventKind::PerimeterBreach,
        interval: tamper_interval,
        uncertainty_reason: None,
        zone_ids: vec![],
        track_ids: vec![],
        probability: ProbabilityInterval::new(0.5, 0.5)?,
        evidence: vec![t1],
        model_receipts: vec![],
        decision_path: sample_decision_path("time-stale-genesis"),
    };
    let mut lineage = EventLineage::new(genesis)?;
    assert!(lineage.has_open_sensor_tamper());

    // Restoration captured earlier in time: 50000..2050100 (before the tamper)
    let stale_interval = CaptureInterval::new(TimestampNs(50_000), TimestampNs(2_050_100))?;
    let r_stale = EventEvidence {
        digest: ContentDigest::sha256(b"restoration-past-time"),
        class: EvidenceClass::Derived,
        failure_domain: "cam-1".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorIntegrityRestoration,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:cam-1")),
    };
    let params = transition_params(
        EventState::Witnessed,
        stale_interval,
        vec![sample_evidence("cam-1", true), r_stale],
    )?;
    let res = lineage.transition(params);
    assert!(res.is_ok());
    // The time-stale restoration MUST NOT retire the tamper
    assert!(lineage.has_open_sensor_tamper());
    assert!(lineage.open_sensor_tamper_domains().contains("cam-1"));
    Ok(())
}

/// Behaviour regression: a retired tamper is never carried forward once its domain reopens.
///
/// The reviewer's M8 mutant (dropping the `seen_restorations` check) is equivalent, because
/// `seen_lineage_digests` already refuses every digest an earlier batch retained; the check was
/// removed and this test does not claim to kill that mutant.
#[test]
fn test_m8_reopened_domain_does_not_carry_forward_retired_tamper() -> Result<(), Box<dyn Error>> {
    let event_id = EventId::parse("event:tamper:m8-retired-tamper-check")?;
    let t1_digest = ContentDigest::sha256(b"tamper-t1");
    let t1 = EventEvidence {
        digest: t1_digest,
        class: EvidenceClass::Derived,
        failure_domain: "cam-1".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorTamper,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:cam-1")),
    };
    let genesis = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_string(),
        event_id: event_id.clone(),
        revision: 1,
        supersedes: None,
        state: EventState::Hypothesized,
        kind: EventKind::PerimeterBreach,
        interval: CaptureInterval::new(TimestampNs(100), TimestampNs(200))?,
        uncertainty_reason: None,
        zone_ids: vec![],
        track_ids: vec![],
        probability: ProbabilityInterval::new(0.5, 0.5)?,
        evidence: vec![t1],
        model_receipts: vec![],
        decision_path: sample_decision_path("m8-genesis"),
    };
    let mut lineage = EventLineage::new(genesis)?;
    assert!(lineage.has_open_sensor_tamper());

    // Rev 2: Valid restoration R1 retires T1
    let r1 = EventEvidence {
        digest: ContentDigest::sha256(b"restoration-r1"),
        class: EvidenceClass::Derived,
        failure_domain: "cam-1".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorIntegrityRestoration,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:cam-1")),
    };
    let params_r1 = transition_params(
        EventState::Witnessed,
        CaptureInterval::new(TimestampNs(300), TimestampNs(400))?,
        vec![sample_evidence("cam-1", true), r1],
    )?;
    lineage.transition(params_r1)?;
    assert!(!lineage.has_open_sensor_tamper());

    // Rev 3: A new tamper T2 occurs on the same domain cam-1
    let t2_digest = ContentDigest::sha256(b"tamper-t2");
    let t2 = EventEvidence {
        digest: t2_digest,
        class: EvidenceClass::Derived,
        failure_domain: "cam-1".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorTamper,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:cam-1")),
    };
    let params_t2 = transition_params(
        EventState::Indeterminate,
        CaptureInterval::new(TimestampNs(500), TimestampNs(600))?,
        vec![sample_evidence("cam-1", true), t2],
    )?;
    lineage.transition(params_t2)?;
    assert!(lineage.has_open_sensor_tamper());

    // Rev 4: Transition to Indeterminate. Carry-forward must ONLY carry forward T2, NEVER retired T1!
    let params_rev4 = transition_params(
        EventState::Indeterminate,
        CaptureInterval::new(TimestampNs(700), TimestampNs(800))?,
        vec![sample_evidence("cam-1", true)],
    )?;
    let rev4 = lineage.transition(params_rev4)?;
    // Rev 4 must NOT contain the retired T1 digest!
    assert!(
        !rev4.evidence.iter().any(|e| e.digest == t1_digest),
        "retired tamper T1 must never be carried forward into new revisions"
    );
    assert!(
        rev4.evidence.iter().any(|e| e.digest == t2_digest),
        "active unretired tamper T2 must be carried forward"
    );
    Ok(())
}

/// Behaviour regression: a restoration reusing the tamper's own digest retires nothing.
///
/// The reviewer's M9 mutant (dropping the `t.digest != edge.digest` check) is equivalent, because
/// the open tamper's digest is already in `seen_lineage_digests`; the check was removed and this
/// test does not claim to kill that mutant.
#[test]
fn test_m9_restoration_reusing_tamper_digest_refused() -> Result<(), Box<dyn Error>> {
    let event_id = EventId::parse("event:tamper:m9-tamper-digest-reuse")?;
    let t_digest = ContentDigest::sha256(b"shared-tamper-digest");
    let t = EventEvidence {
        digest: t_digest,
        class: EvidenceClass::Derived,
        failure_domain: "cam-1".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorTamper,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:cam-1")),
    };
    let genesis = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_string(),
        event_id: event_id.clone(),
        revision: 1,
        supersedes: None,
        state: EventState::Hypothesized,
        kind: EventKind::PerimeterBreach,
        interval: CaptureInterval::new(TimestampNs(100), TimestampNs(200))?,
        uncertainty_reason: None,
        zone_ids: vec![],
        track_ids: vec![],
        probability: ProbabilityInterval::new(0.5, 0.5)?,
        evidence: vec![t],
        model_receipts: vec![],
        decision_path: sample_decision_path("m9-genesis"),
    };
    let mut lineage = EventLineage::new(genesis)?;
    assert!(lineage.has_open_sensor_tamper());

    // Restoration attempts to reuse the tamper's own digest
    let r_reused = EventEvidence {
        digest: t_digest,
        class: EvidenceClass::Derived,
        failure_domain: "cam-1".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorIntegrityRestoration,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:cam-1")),
    };
    let params = transition_params(
        EventState::Witnessed,
        CaptureInterval::new(TimestampNs(300), TimestampNs(400))?,
        vec![sample_evidence("cam-1", true), r_reused],
    )?;
    lineage.transition(params)?;
    assert!(lineage.has_open_sensor_tamper());
    assert!(lineage.open_sensor_tamper_domains().contains("cam-1"));
    Ok(())
}

#[test]
fn test_pc4_pc5_restoration_reusing_prior_lineage_digests_refused() -> Result<(), Box<dyn Error>> {
    let event_id = EventId::parse("event:tamper:pc4-pc5-reused-digests")?;
    let support_digest = ContentDigest::sha256(b"prior-support-edge-pc4");
    let other_tamper_digest = ContentDigest::sha256(b"other-sensor-tamper-pc5");
    let cam1_tamper = EventEvidence {
        digest: ContentDigest::sha256(b"cam1-tamper"),
        class: EvidenceClass::Derived,
        failure_domain: "cam-1".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorTamper,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:cam-1")),
    };
    let cam2_tamper = EventEvidence {
        digest: other_tamper_digest,
        class: EvidenceClass::Derived,
        failure_domain: "cam-2".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorTamper,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:cam-2")),
    };
    let support_edge = EventEvidence {
        digest: support_digest,
        class: EvidenceClass::Derived,
        failure_domain: "radar-1".to_string(),
        supports: true,
        relation: EvidenceEdgeRelation::Supports,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:radar-1")),
    };
    let genesis = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_string(),
        event_id: event_id.clone(),
        revision: 1,
        supersedes: None,
        state: EventState::Hypothesized,
        kind: EventKind::PerimeterBreach,
        interval: CaptureInterval::new(TimestampNs(100), TimestampNs(200))?,
        uncertainty_reason: None,
        zone_ids: vec![],
        track_ids: vec![],
        probability: ProbabilityInterval::new(0.5, 0.5)?,
        evidence: vec![cam1_tamper, cam2_tamper, support_edge],
        model_receipts: vec![],
        decision_path: sample_decision_path("pc4-pc5-genesis"),
    };
    let mut lineage = EventLineage::new(genesis)?;

    // PC4: Restoration for cam-1 reuses support_digest from revision 1
    let r_pc4 = EventEvidence {
        digest: support_digest,
        class: EvidenceClass::Derived,
        failure_domain: "cam-1".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorIntegrityRestoration,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:cam-1")),
    };
    let params_pc4 = transition_params(
        EventState::Indeterminate,
        CaptureInterval::new(TimestampNs(300), TimestampNs(400))?,
        vec![sample_evidence("cam-1", true), r_pc4],
    )?;
    lineage.transition(params_pc4)?;
    assert!(lineage.open_sensor_tamper_domains().contains("cam-1"));

    // PC5: Restoration for cam-1 reuses other_tamper_digest (from cam-2)
    let r_pc5 = EventEvidence {
        digest: other_tamper_digest,
        class: EvidenceClass::Derived,
        failure_domain: "cam-1".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorIntegrityRestoration,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:cam-1")),
    };
    let params_pc5 = transition_params(
        EventState::Indeterminate,
        CaptureInterval::new(TimestampNs(500), TimestampNs(600))?,
        vec![sample_evidence("cam-1", true), r_pc5],
    )?;
    lineage.transition(params_pc5)?;
    assert!(lineage.open_sensor_tamper_domains().contains("cam-1"));

    Ok(())
}

#[test]
fn test_pc3a_supersede_chain_prevents_reciting_old_restoration() -> Result<(), Box<dyn Error>> {
    let event_id = EventId::parse("event:tamper:pc3a-recite-chain")?;
    let t1 = EventEvidence {
        digest: ContentDigest::sha256(b"pc3a-t1"),
        class: EvidenceClass::Derived,
        failure_domain: "cam-1".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorTamper,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:cam-1")),
    };
    let rev1 = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_string(),
        event_id: event_id.clone(),
        revision: 1,
        supersedes: None,
        state: EventState::Hypothesized,
        kind: EventKind::PerimeterBreach,
        interval: CaptureInterval::new(TimestampNs(100), TimestampNs(200))?,
        uncertainty_reason: None,
        zone_ids: vec![],
        track_ids: vec![],
        probability: ProbabilityInterval::new(0.5, 0.5)?,
        evidence: vec![t1],
        model_receipts: vec![],
        decision_path: sample_decision_path("pc3a-rev1"),
    };

    // Rev 2: Restoration R1 retires T1
    let r1_digest = ContentDigest::sha256(b"pc3a-r1");
    let r1 = EventEvidence {
        digest: r1_digest,
        class: EvidenceClass::Derived,
        failure_domain: "cam-1".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorIntegrityRestoration,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:cam-1")),
    };
    let rev2 = rev1.supersede(
        EventSupersedeParams {
            state: EventState::Witnessed,
            kind: rev1.kind,
            interval: CaptureInterval::new(TimestampNs(300), TimestampNs(400))?,
            uncertainty_reason: None,
            zone_ids: vec![],
            track_ids: vec![],
            probability: rev1.probability,
            evidence: vec![sample_evidence("cam-1", true), r1.clone()],
            model_receipts: vec![],
            decision_path: sample_decision_path("pc3a-rev2"),
        },
        std::slice::from_ref(&rev1),
    )?;

    // Rev 3: New tamper T2
    let t2 = EventEvidence {
        digest: ContentDigest::sha256(b"pc3a-t2"),
        class: EvidenceClass::Derived,
        failure_domain: "cam-1".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorTamper,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:cam-1")),
    };
    let rev3 = rev2.supersede(
        EventSupersedeParams {
            state: EventState::Indeterminate,
            kind: rev2.kind,
            interval: CaptureInterval::new(TimestampNs(500), TimestampNs(600))?,
            uncertainty_reason: None,
            zone_ids: vec![],
            track_ids: vec![],
            probability: rev2.probability,
            evidence: vec![sample_evidence("cam-1", true), t2],
            model_receipts: vec![],
            decision_path: sample_decision_path("pc3a-rev3"),
        },
        &[rev1.clone(), rev2.clone()],
    )?;

    // Rev 4: Attempt to supersede Rev 3 to Corroborated by re-citing R1
    let chain = [rev1.clone(), rev2.clone(), rev3.clone()];
    let res = rev3.supersede(
        EventSupersedeParams {
            state: EventState::Corroborated,
            kind: rev3.kind,
            interval: CaptureInterval::new(TimestampNs(700), TimestampNs(800))?,
            uncertainty_reason: None,
            zone_ids: vec![],
            track_ids: vec![],
            probability: rev3.probability,
            evidence: vec![
                sample_evidence("cam-1", true),
                sample_evidence("cam-2", true),
                r1,
            ],
            model_receipts: vec![],
            decision_path: sample_decision_path("pc3a-rev4"),
        },
        &chain,
    );
    assert_eq!(
        res,
        Err(EventDecodeError::Contract(
            ContractError::SensorIntegrityRisk
        ))
    );
    Ok(())
}

#[test]
fn test_cross_sensor_restoration_refused() -> Result<(), Box<dyn Error>> {
    let event_id = EventId::parse("event:tamper:cross-sensor")?;
    let genesis = sample_genesis_hypothesis(&event_id, "cam-1", true)?;
    let mut lineage = EventLineage::new(genesis.clone())?;

    let cross_id_restoration = EventEvidence {
        digest: ContentDigest::sha256(b"cross-sensor-restoration"),
        class: EvidenceClass::Derived,
        failure_domain: "cam-1".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorIntegrityRestoration,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:different-sensor")),
    };
    let params_cross = transition_params(
        EventState::Witnessed,
        later_interval(1)?,
        vec![sample_evidence("cam-1", true), cross_id_restoration],
    )?;
    let res = lineage.transition(params_cross);
    assert!(res.is_ok());
    assert!(lineage.has_open_sensor_tamper());
    assert!(lineage.open_sensor_tamper_domains().contains("cam-1"));

    let diff_domain_restoration = EventEvidence {
        digest: ContentDigest::sha256(b"diff-domain-restoration"),
        class: EvidenceClass::Derived,
        failure_domain: "cam-other".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorIntegrityRestoration,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:cam-1")),
    };
    let params_diff = transition_params(
        EventState::Indeterminate,
        later_interval(2)?,
        vec![sample_evidence("cam-1", true), diff_domain_restoration],
    )?;
    let res_diff = lineage.transition(params_diff);
    assert!(res_diff.is_ok());
    assert!(lineage.has_open_sensor_tamper());
    assert!(lineage.open_sensor_tamper_domains().contains("cam-1"));

    Ok(())
}

#[test]
fn test_re_cited_restoration_refused() -> Result<(), Box<dyn Error>> {
    let event_id = EventId::parse("event:tamper:re-cited")?;
    let genesis = sample_genesis_hypothesis(&event_id, "cam-1", true)?;
    let mut lineage = EventLineage::new(genesis.clone())?;

    let r1 = restoration_evidence("cam-1");
    let params_r1 = transition_params(
        EventState::Witnessed,
        later_interval(1)?,
        vec![sample_evidence("cam-1", true), r1.clone()],
    )?;
    assert!(lineage.transition(params_r1).is_ok());
    assert!(!lineage.has_open_sensor_tamper());

    let t3 = EventEvidence {
        digest: ContentDigest::sha256(b"evidence:cam-1:tamper-2"),
        class: EvidenceClass::Derived,
        failure_domain: "cam-1".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::SensorTamper,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:cam-1")),
    };
    let params_t3 = transition_params(
        EventState::Indeterminate,
        later_interval(2)?,
        vec![sample_evidence("cam-1", true), t3],
    )?;
    assert!(lineage.transition(params_t3).is_ok());
    assert!(lineage.has_open_sensor_tamper());

    let params_re_cite = transition_params(
        EventState::Indeterminate,
        later_interval(3)?,
        vec![sample_evidence("cam-1", true), r1],
    )?;
    assert!(lineage.transition(params_re_cite).is_ok());
    assert!(lineage.has_open_sensor_tamper());
    assert!(lineage.open_sensor_tamper_domains().contains("cam-1"));

    Ok(())
}

#[test]
fn test_dedup_by_digest_and_relation() -> Result<(), Box<dyn Error>> {
    let event_id = EventId::parse("event:tamper:dedup")?;
    let genesis = sample_genesis_hypothesis(&event_id, "cam-1", true)?;
    let mut lineage = EventLineage::new(genesis.clone())?;

    let prior_tamper = genesis
        .evidence
        .iter()
        .find(|e| e.reports_sensor_tamper())
        .ok_or("missing tamper edge")?;
    let shared_digest = prior_tamper.digest;

    let edge_derived = EventEvidence {
        digest: shared_digest,
        class: EvidenceClass::Derived,
        failure_domain: "cam-1".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::DerivedFrom,
        capsule_digest: None,
        identity_digest: None,
    };
    let params = transition_params(
        EventState::Witnessed,
        genesis.interval,
        vec![sample_evidence("cam-1", true), edge_derived],
    )?;
    let rev = lineage.transition(params)?;
    let has_tamper = rev
        .evidence
        .iter()
        .any(|e| e.digest == shared_digest && e.relation == EvidenceEdgeRelation::SensorTamper);
    let has_derived = rev
        .evidence
        .iter()
        .any(|e| e.digest == shared_digest && e.relation == EvidenceEdgeRelation::DerivedFrom);
    assert!(has_tamper, "sticky tamper edge should be carried forward");
    assert!(
        has_derived,
        "distinct relation with same digest must not be deduplicated away"
    );

    Ok(())
}

/// Round 4 (fss-2uftm): the r2u3 review probes, committed, plus the replay/verification agreement,
/// strict capture ordering and full canonical-digest coverage contracts.
mod round4 {
    use std::collections::BTreeMap;
    use std::error::Error;

    use fss_core::event::{
        EventLineage, EventSupersedeParams, EventTransitionError, EventTransitionParams,
        TamperRecord, apply_revision_tamper_step, compute_sensor_tamper_status,
        compute_sensor_tamper_status_with_interval,
    };
    use fss_core::{
        CaptureInterval, ContentDigest, ContractError, DecisionPath, EventDecodeError,
        EventEvidence, EventHypothesis, EventId, EventKind, EventState, EvidenceClass,
        EvidenceDelta, EvidenceEdgeRelation, ObjectId, Plane, ProbabilityInterval,
        SensorTamperStatus, TimestampNs,
    };

    fn iv(a: i128, b: i128) -> Result<CaptureInterval, ContractError> {
        CaptureInterval::new(TimestampNs(a), TimestampNs(b))
    }

    fn path(label: &str) -> DecisionPath {
        DecisionPath {
            policy_generation: ContentDigest::sha256(format!("r4policy:{label}").as_bytes()),
            fingerprint: ContentDigest::sha256(format!("r4fp:{label}").as_bytes()),
            abstained: false,
            abstention_reason: None,
        }
    }

    fn edge(tag: &str, domain: &str, rel: EvidenceEdgeRelation) -> EventEvidence {
        EventEvidence {
            digest: ContentDigest::sha256(tag.as_bytes()),
            class: EvidenceClass::Derived,
            failure_domain: domain.to_owned(),
            supports: rel.required_supports_flag(),
            relation: rel,
            capsule_digest: None,
            identity_digest: Some(ContentDigest::sha256(format!("sensor:{domain}").as_bytes())),
        }
    }

    fn sup(tag: &str, d: &str) -> EventEvidence {
        edge(tag, d, EvidenceEdgeRelation::Supports)
    }

    fn tam(tag: &str, d: &str) -> EventEvidence {
        edge(tag, d, EvidenceEdgeRelation::SensorTamper)
    }

    fn res(tag: &str, d: &str) -> EventEvidence {
        edge(tag, d, EvidenceEdgeRelation::SensorIntegrityRestoration)
    }

    fn sp(
        state: EventState,
        interval: CaptureInterval,
        evidence: Vec<EventEvidence>,
        label: &str,
    ) -> Result<EventSupersedeParams, ContractError> {
        Ok(EventSupersedeParams {
            state,
            kind: EventKind::PerimeterBreach,
            interval,
            uncertainty_reason: None,
            zone_ids: vec![],
            track_ids: vec![],
            probability: ProbabilityInterval::new(0.5, 0.9)?,
            evidence,
            model_receipts: vec![],
            decision_path: path(label),
        })
    }

    fn tp(
        state: EventState,
        interval: CaptureInterval,
        evidence: Vec<EventEvidence>,
        label: &str,
    ) -> Result<EventTransitionParams, ContractError> {
        Ok(EventTransitionParams {
            target_state: state,
            kind: EventKind::PerimeterBreach,
            interval,
            uncertainty_reason: None,
            zone_ids: vec![],
            track_ids: vec![],
            probability: ProbabilityInterval::new(0.5, 0.9)?,
            evidence,
            model_receipts: vec![],
            decision_path: path(label),
            urgent_single_sensor: false,
        })
    }

    fn genesis(
        id: &str,
        interval: CaptureInterval,
        evidence: Vec<EventEvidence>,
    ) -> Result<EventHypothesis, Box<dyn Error>> {
        let g = EventHypothesis {
            schema: EventHypothesis::SCHEMA.to_string(),
            event_id: EventId::parse(id)?,
            revision: 1,
            supersedes: None,
            state: EventState::Hypothesized,
            kind: EventKind::PerimeterBreach,
            interval,
            uncertainty_reason: None,
            zone_ids: vec![],
            track_ids: vec![],
            probability: ProbabilityInterval::new(0.5, 0.5)?,
            evidence,
            model_receipts: vec![],
            decision_path: path("genesis"),
        };
        g.verify()?;
        Ok(g)
    }

    /// A successor built by hand, bypassing `supersede`/`transition`, as a replayed ledger would
    /// hold it.
    fn next_rev(
        prior: &EventHypothesis,
        state: EventState,
        interval: CaptureInterval,
        evidence: Vec<EventEvidence>,
        tag: &str,
    ) -> Result<EventHypothesis, Box<dyn Error>> {
        Ok(EventHypothesis {
            schema: EventHypothesis::SCHEMA.to_string(),
            event_id: prior.event_id.clone(),
            revision: prior.revision + 1,
            supersedes: Some(prior.revision_digest()),
            state,
            kind: EventKind::PerimeterBreach,
            interval,
            uncertainty_reason: None,
            zone_ids: vec![],
            track_ids: vec![],
            probability: ProbabilityInterval::new(0.8, 0.9)?,
            evidence,
            model_receipts: vec![],
            decision_path: path(tag),
        })
    }

    /// rev1 (T1) -> rev2 (R1 retires T1) -> rev3 (new T2), built through the honest chain.
    fn pc3a_chain(id: &str) -> Result<[EventHypothesis; 3], Box<dyn Error>> {
        let rev1 = genesis(id, iv(100, 200)?, vec![tam("r4-t1", "cam-1")])?;
        let rev2 = rev1.supersede(
            sp(
                EventState::Witnessed,
                iv(300, 400)?,
                vec![sup("r4-s1", "cam-1"), res("r4-r1", "cam-1")],
                "rev2",
            )?,
            std::slice::from_ref(&rev1),
        )?;
        let rev3 = rev2.supersede(
            sp(
                EventState::Indeterminate,
                iv(500, 600)?,
                vec![sup("r4-s2", "cam-1"), tam("r4-t2", "cam-1")],
                "rev3",
            )?,
            &[rev1.clone(), rev2.clone()],
        )?;
        Ok([rev1, rev2, rev3])
    }

    /// Corroborated successor that re-cites the old restoration R1 in an attempt to retire T2.
    fn recite() -> Result<EventSupersedeParams, Box<dyn Error>> {
        Ok(sp(
            EventState::Corroborated,
            iv(700, 800)?,
            vec![
                sup("r4-s3", "cam-1"),
                sup("r4-s4", "cam-2"),
                res("r4-r1", "cam-1"),
            ],
            "rev4",
        )?)
    }

    const MISMATCH: EventDecodeError =
        EventDecodeError::Contract(ContractError::SupersessionMismatch);

    #[test]
    fn pc3a_full_chain_recital_refused() -> Result<(), Box<dyn Error>> {
        let [r1, r2, r3] = pc3a_chain("event:r4:pc3a-full")?;
        let out = r3.supersede(recite()?, &[r1, r2, r3.clone()]);
        assert_eq!(
            out.err(),
            Some(EventDecodeError::Contract(
                ContractError::SensorIntegrityRisk
            ))
        );
        Ok(())
    }

    #[test]
    fn pc3a_empty_chain_refused() -> Result<(), Box<dyn Error>> {
        let [_r1, _r2, r3] = pc3a_chain("event:r4:pc3a-empty")?;
        assert_eq!(r3.supersede(recite()?, &[]).err(), Some(MISMATCH));
        // No fallback to `[self]` even for a genesis revision.
        let g = genesis(
            "event:r4:pc3a-empty-genesis",
            iv(1, 2)?,
            vec![sup("r4-e1", "cam-1")],
        )?;
        let params = sp(
            EventState::Witnessed,
            iv(3, 4)?,
            vec![sup("r4-e2", "cam-1")],
            "e",
        )?;
        assert_eq!(g.supersede(params, &[]).err(), Some(MISMATCH));
        Ok(())
    }

    #[test]
    fn pc3a_self_only_chain_refused_when_self_has_predecessors() -> Result<(), Box<dyn Error>> {
        let [r1, r2, r3] = pc3a_chain("event:r4:pc3a-self")?;
        assert_eq!(
            r3.supersede(recite()?, std::slice::from_ref(&r3)).err(),
            Some(MISMATCH)
        );
        // A chain ending in self that is missing the genesis is also not self's lineage.
        assert_eq!(
            r3.supersede(recite()?, &[r2.clone(), r3.clone()]).err(),
            Some(MISMATCH)
        );
        // Control: `[self]` is the whole lineage of a genesis revision.
        let ok = r1.supersede(
            sp(
                EventState::Witnessed,
                iv(300, 400)?,
                vec![sup("r4-c1", "cam-1")],
                "c",
            )?,
            std::slice::from_ref(&r1),
        );
        assert!(ok.is_ok(), "{ok:?}");
        Ok(())
    }

    #[test]
    fn pc3a_unrelated_chain_refused() -> Result<(), Box<dyn Error>> {
        let [_r1, r2, r3] = pc3a_chain("event:r4:pc3a-unrel")?;
        let other = genesis(
            "event:r4:pc3a-other",
            iv(1, 2)?,
            vec![sup("r4-o1", "cam-9")],
        )?;
        assert_eq!(
            r3.supersede(recite()?, std::slice::from_ref(&other)).err(),
            Some(MISMATCH)
        );
        // Same length and ending in self, but rooted in another event: refused by verification.
        let spliced = r3.supersede(recite()?, &[other, r2, r3.clone()]);
        assert!(spliced.is_err(), "{spliced:?}");
        // Same event id, a clean fake prefix, ending in self and of the right length: only chain
        // verification refuses it. Without it the old restoration R1, absent from the fake prefix,
        // would retire T2 and the recital would reach Corroborated (kills MX2).
        let f1 = genesis(
            "event:r4:pc3a-unrel",
            iv(100, 200)?,
            vec![sup("r4-f1", "cam-1")],
        )?;
        let f2 = next_rev(
            &f1,
            EventState::Witnessed,
            iv(300, 400)?,
            vec![sup("r4-f2", "cam-1")],
            "f2",
        )?;
        let fake_prefix = r3.supersede(recite()?, &[f1, f2, r3.clone()]);
        assert!(fake_prefix.is_err(), "{fake_prefix:?}");
        Ok(())
    }

    #[test]
    fn pr6_transition_time_stale_restoration_keeps_tamper() -> Result<(), Box<dyn Error>> {
        let g = genesis(
            "event:r4:pr6-tr",
            iv(5_000_000, 7_000_100)?,
            vec![tam("r4-6-t", "cam-1")],
        )?;
        let mut l = EventLineage::new(g)?;
        l.transition(tp(
            EventState::Witnessed,
            iv(50_000, 2_050_100)?,
            vec![sup("r4-6-s", "cam-1"), res("r4-6-r", "cam-1")],
            "r2",
        )?)?;
        assert!(l.has_open_sensor_tamper());
        Ok(())
    }

    /// Replays `chain` through `EventLineage::replay_from_deltas`, the ledger replay entrypoint.
    fn replay_from_deltas_ok(chain: &[EventHypothesis]) -> Result<bool, Box<dyn Error>> {
        let Some(first) = chain.first() else {
            return Ok(false);
        };
        let mut payloads = BTreeMap::new();
        let mut deltas = Vec::new();
        for rev in chain {
            let digest = rev.revision_digest();
            payloads.insert(digest, rev.clone());
            deltas.push(EvidenceDelta {
                delta_id: format!("delta:{}", rev.revision),
                family: "event_revision".to_string(),
                object_id: ObjectId::parse(rev.event_id.as_str())?,
                prior_generation: rev.revision.checked_sub(1).filter(|p| *p > 0),
                new_generation: rev.revision,
                validity: rev.interval,
                plane: Plane::Cognition,
                payload_digest: digest,
                witness_digest: Some(digest),
                operation_id: None,
            });
        }
        Ok(
            EventLineage::replay_from_deltas(&first.event_id, &deltas, |d| {
                payloads.get(d).cloned()
            })
            .is_ok(),
        )
    }

    /// `[verify_chain, from_revisions, replay_from_deltas]` verdicts (true = accepted).
    fn verdicts(chain: &[EventHypothesis]) -> Result<[bool; 3], Box<dyn Error>> {
        Ok([
            EventHypothesis::verify_chain(chain).is_ok(),
            EventLineage::from_revisions(chain.to_vec()).is_ok(),
            replay_from_deltas_ok(chain)?,
        ])
    }

    /// PR6 via replay: g = tamper at [5e6, 7_000_100]; rev2 Witnessed carrying it; rev3
    /// Corroborated whose only retirement is a restoration captured at rev3's own interval.
    fn pr6_replay_chain(
        id: &str,
        rev3_interval: CaptureInterval,
        tag: &str,
    ) -> Result<Vec<EventHypothesis>, Box<dyn Error>> {
        let t = tam(&format!("{id}-t"), "cam-1");
        let g = genesis(id, iv(5_000_000, 7_000_100)?, vec![t.clone()])?;
        let r2 = next_rev(
            &g,
            EventState::Witnessed,
            iv(8_000_000, 9_000_000)?,
            vec![sup(&format!("{id}-w"), "cam-1"), t],
            "r2",
        )?;
        let r3 = next_rev(
            &r2,
            EventState::Corroborated,
            rev3_interval,
            vec![
                sup(&format!("{tag}-s1"), "cam-1"),
                sup(&format!("{tag}-s2"), "cam-2"),
                res(&format!("{tag}-r"), "cam-1"),
            ],
            tag,
        )?;
        Ok(vec![g, r2, r3])
    }

    #[test]
    fn pr6_replay_time_stale_corroborated_refused_like_verify_chain() -> Result<(), Box<dyn Error>>
    {
        let control = pr6_replay_chain("event:r4:pr6-replay-ok", iv(9_500_000, 10_000_000)?, "ok")?;
        assert_eq!(verdicts(&control)?, [true, true, true]);

        let stale = pr6_replay_chain("event:r4:pr6-replay-stale", iv(50_000, 2_050_100)?, "st")?;
        let vc = EventHypothesis::verify_chain(&stale);
        let fr = EventLineage::from_revisions(stale.clone()).map(|_| ());
        assert_eq!(
            vc,
            Err(EventDecodeError::Contract(
                ContractError::SensorIntegrityRisk
            ))
        );
        assert_eq!(fr, Err(EventTransitionError::SensorIntegrityRisk));
        // Identical verdict from every entrypoint on the stale-restoration chain.
        assert_eq!(verdicts(&stale)?, [false, false, false]);
        Ok(())
    }

    #[test]
    fn replay_and_verify_chain_agree_on_every_chain() -> Result<(), Box<dyn Error>> {
        let mut cases: Vec<(&str, Vec<EventHypothesis>, bool)> = vec![
            (
                "later restoration",
                pr6_replay_chain("event:r4:agree-later", iv(9_500_000, 10_000_000)?, "a1")?,
                true,
            ),
            (
                "stale restoration",
                pr6_replay_chain("event:r4:agree-stale", iv(50_000, 2_050_100)?, "a2")?,
                false,
            ),
            (
                "overlapping restoration",
                pr6_replay_chain("event:r4:agree-overlap", iv(6_000_000, 9_500_000)?, "a3")?,
                false,
            ),
            (
                "restoration starting at the tamper's end",
                pr6_replay_chain("event:r4:agree-edge", iv(7_000_100, 9_500_000)?, "a4")?,
                false,
            ),
        ];

        // A non-vetoed revision that silently drops an unretired tamper.
        let t = tam("r4-drop-t", "cam-1");
        let g = genesis("event:r4:agree-drop", iv(100, 200)?, vec![t.clone()])?;
        let dropped = next_rev(
            &g,
            EventState::Witnessed,
            iv(300, 400)?,
            vec![sup("r4-drop-s", "cam-1")],
            "drop",
        )?;
        cases.push(("dropped carry-forward", vec![g.clone(), dropped], false));
        let carried = next_rev(
            &g,
            EventState::Witnessed,
            iv(300, 400)?,
            vec![sup("r4-carry-s", "cam-1"), t],
            "carry",
        )?;
        cases.push(("carried forward", vec![g, carried], true));

        // A rule only replay used to enforce: duplicate evidence within a revision.
        let g2 = genesis(
            "event:r4:agree-dup",
            iv(100, 200)?,
            vec![sup("r4-dup-g", "cam-1")],
        )?;
        let dup = next_rev(
            &g2,
            EventState::Witnessed,
            iv(300, 400)?,
            vec![sup("r4-dup", "cam-1"), sup("r4-dup", "cam-1")],
            "dup",
        )?;
        cases.push(("duplicate evidence", vec![g2, dup], false));
        let mut g3 = genesis(
            "event:r4:agree-gen",
            iv(100, 200)?,
            vec![sup("r4-gen", "cam-1")],
        )?;
        g3.state = EventState::Witnessed;

        for (label, chain, accepted) in &cases {
            assert_eq!(
                verdicts(chain)?,
                [*accepted; 3],
                "replay and verify_chain disagree or misjudge: {label}"
            );
        }

        // The one documented difference: an `EventLineage` begins `Hypothesized` (its lifecycle
        // rule, applied by replay), while a verified chain may begin at a later state, as the
        // reference policy's first published revision does.
        assert_eq!(verdicts(&[g3])?, [true, false, false]);
        Ok(())
    }

    /// Low: a restoration whose capture overlaps the tamper's, or starts exactly at its end, does
    /// not retire it; one starting strictly after the tamper's end does.
    #[test]
    fn overlapping_restoration_does_not_retire_tamper() -> Result<(), Box<dyn Error>> {
        let cases = [
            ("identical", iv(5_000_000, 7_000_100)?, true),
            ("starts inside", iv(6_000_000, 8_000_000)?, true),
            ("covers", iv(4_000_000, 9_000_000)?, true),
            ("starts at end", iv(7_000_100, 8_000_000)?, true),
            ("starts after end", iv(7_000_101, 8_000_000)?, false),
        ];
        for (label, interval, stays_open) in cases {
            let g = genesis(
                &format!("event:r4:overlap-{}", label.replace(' ', "-")),
                iv(5_000_000, 7_000_100)?,
                vec![tam(&format!("r4-ov-t-{label}"), "cam-1")],
            )?;
            let mut l = EventLineage::new(g.clone())?;
            l.transition(tp(
                EventState::Witnessed,
                interval,
                vec![
                    sup(&format!("r4-ov-s-{label}"), "cam-1"),
                    res(&format!("r4-ov-r-{label}"), "cam-1"),
                ],
                "r2",
            )?)?;
            assert_eq!(
                l.has_open_sensor_tamper(),
                stays_open,
                "transition: {label}"
            );
            let status = compute_sensor_tamper_status_with_interval(
                [&g],
                Some(&[res(&format!("r4-ov-r2-{label}"), "cam-1")]),
                Some(interval),
            );
            assert_eq!(status.has_open_tamper(), stays_open, "status: {label}");
        }
        Ok(())
    }

    /// Current evidence with no capture interval of its own is not ordered after any tamper, so it
    /// never borrows the previous revision's interval to retire one.
    #[test]
    fn current_evidence_without_interval_never_retires() -> Result<(), Box<dyn Error>> {
        let g = genesis(
            "event:r4:no-interval",
            iv(100, 200)?,
            vec![tam("r4-ni-t", "cam-1")],
        )?;
        let unordered = compute_sensor_tamper_status([&g], Some(&[res("r4-ni-r", "cam-1")]));
        assert!(unordered.has_open_tamper());
        let ordered = compute_sensor_tamper_status_with_interval(
            [&g],
            Some(&[res("r4-ni-r", "cam-1")]),
            Some(iv(300, 400)?),
        );
        assert!(!ordered.has_open_tamper());

        // With a later revision in the history, borrowing its interval would order the unordered
        // restoration after the tamper and retire it (the round-3 replay defect). It must not.
        let r2 = next_rev(
            &g,
            EventState::Witnessed,
            iv(300, 400)?,
            vec![sup("r4-ni-s", "cam-1"), tam("r4-ni-t", "cam-1")],
            "r2",
        )?;
        let borrowed = compute_sensor_tamper_status([&g, &r2], Some(&[res("r4-ni-r2", "cam-1")]));
        assert!(borrowed.has_open_tamper());
        Ok(())
    }

    #[test]
    fn pr6_concurrent_restoration_keeps_tamper() -> Result<(), Box<dyn Error>> {
        let g = genesis(
            "event:r4:pr6-conc",
            iv(5_000_000, 7_000_100)?,
            vec![tam("r4-6c-t", "cam-1")],
        )?;
        let mut l = EventLineage::new(g)?;
        l.transition(tp(
            EventState::Witnessed,
            iv(5_000_000, 7_000_100)?,
            vec![sup("r4-6c-s", "cam-1"), res("r4-6c-r", "cam-1")],
            "r2",
        )?)?;
        assert!(l.has_open_sensor_tamper());
        Ok(())
    }

    /// PC4 / PC5 through supersede, plus a same-batch digest collision.
    #[test]
    fn pc4_pc5_supersede_and_same_batch() -> Result<(), Box<dyn Error>> {
        let t2 = tam("r4-45-t2", "cam-2");
        let s = sup("r4-45-s", "radar-1");
        let g = genesis(
            "event:r4:pc45",
            iv(100, 200)?,
            vec![tam("r4-45-t", "cam-1"), t2.clone(), s.clone()],
        )?;
        let mut r_pc4 = res("x", "cam-1");
        r_pc4.digest = s.digest;
        let a = g.supersede(
            sp(
                EventState::Indeterminate,
                iv(300, 400)?,
                vec![sup("r4-45-s9", "cam-1"), r_pc4],
                "pc4",
            )?,
            std::slice::from_ref(&g),
        );
        let a_open = a.as_ref().map(|r| {
            compute_sensor_tamper_status([&g, r], None)
                .open_domains
                .contains("cam-1")
        });
        let mut r_pc5 = res("y", "cam-1");
        r_pc5.digest = t2.digest;
        let b = g.supersede(
            sp(
                EventState::Indeterminate,
                iv(300, 400)?,
                vec![sup("r4-45-s8", "cam-1"), r_pc5],
                "pc5",
            )?,
            std::slice::from_ref(&g),
        );
        let b_open = b.as_ref().map(|r| {
            compute_sensor_tamper_status([&g, r], None)
                .open_domains
                .contains("cam-1")
        });
        let fresh = ContentDigest::sha256(b"r4-45-fresh");
        let mut r_sb = res("z", "cam-1");
        r_sb.digest = fresh;
        let mut s_sb = sup("w", "cam-3");
        s_sb.digest = fresh;
        let st = compute_sensor_tamper_status([&g], Some(&[s_sb.clone(), r_sb.clone()]));
        // Ordered after the tamper, only the one-occurrence-per-batch rule keeps a digest that is
        // both a support and a restoration in one batch from retiring it (kills MB); the same
        // restoration alone, ordered after the tamper, does retire it.
        let ordered = compute_sensor_tamper_status_with_interval(
            [&g],
            Some(&[s_sb, r_sb.clone()]),
            Some(iv(300, 400)?),
        );
        assert!(ordered.open_domains.contains("cam-1"));
        let alone = compute_sensor_tamper_status_with_interval(
            [&g],
            Some(std::slice::from_ref(&r_sb)),
            Some(iv(300, 400)?),
        );
        assert!(!alone.open_domains.contains("cam-1"));
        assert!(matches!(a_open, Ok(true) | Err(_)));
        assert!(matches!(b_open, Ok(true) | Err(_)));
        assert!(st.open_domains.contains("cam-1"));
        Ok(())
    }

    /// Carry-forward is per tamper digest: re-citing one open tamper of a domain does not excuse
    /// dropping another open tamper of the same domain.
    #[test]
    fn carry_forward_is_per_tamper_digest() -> Result<(), Box<dyn Error>> {
        let ta = tam("r4-pd-a", "cam-1");
        let tb = tam("r4-pd-b", "cam-1");
        let g = genesis("event:r4:per-digest", iv(100, 200)?, vec![ta.clone(), tb])?;
        let partial = next_rev(
            &g,
            EventState::Witnessed,
            iv(300, 400)?,
            vec![sup("r4-pd-s", "cam-1"), ta],
            "partial",
        )?;
        let mut status = compute_sensor_tamper_status([&g], None);
        assert_eq!(
            apply_revision_tamper_step(&mut status, &partial),
            Err(ContractError::SensorIntegrityRisk)
        );
        assert_eq!(verdicts(&[g, partial])?, [false, false, false]);
        Ok(())
    }

    /// Low: every public field of the status is covered by its canonical digest, so a receipt that
    /// edits any of them no longer matches the published witness.
    #[test]
    fn canonical_digest_covers_every_field() -> Result<(), Box<dyn Error>> {
        // One retired and one open tamper, so every collection of the status is non-empty.
        let g = genesis(
            "event:r4:digest",
            iv(100, 200)?,
            vec![tam("r4-dg-t", "cam-1")],
        )?;
        let r2 = next_rev(
            &g,
            EventState::Witnessed,
            iv(300, 400)?,
            vec![
                sup("r4-dg-s", "cam-1"),
                res("r4-dg-r", "cam-1"),
                tam("r4-dg-t2", "cam-1"),
            ],
            "r2",
        )?;
        let base: SensorTamperStatus = compute_sensor_tamper_status([&g, &r2], None);
        assert!(!base.open_domains.is_empty() && !base.open_tamper_roots.is_empty());
        assert!(!base.restorations.is_empty() && !base.open_tamper_records.is_empty());
        assert!(!base.open_tamper_reports.is_empty() && !base.seen_restorations.is_empty());
        assert!(!base.seen_lineage_digests.is_empty());
        let d = ContentDigest::sha256(b"r4-dg-extra");
        let mut variants: Vec<(&str, SensorTamperStatus)> = Vec::new();

        // Same-length replacements: an encoding that kept only each collection's length would
        // still change digest under insertion, but not under these.
        let mut v = base.clone();
        v.open_domains.clear();
        v.open_domains.insert("cam-x".to_owned());
        variants.push(("open_domains (replaced)", v));
        let mut v = base.clone();
        if let Some(root) = v.open_tamper_roots.first_mut() {
            *root = d;
        }
        variants.push(("open_tamper_roots (replaced)", v));
        let mut v = base.clone();
        if let Some(restoration) = v.restorations.first_mut() {
            restoration.1 = d;
        }
        variants.push(("restorations (replaced)", v));
        let mut v = base.clone();
        if let Some(record) = v.open_tamper_records.first_mut() {
            record.digest = d;
        }
        variants.push(("open_tamper_records (replaced)", v));
        let mut v = base.clone();
        if let Some(report) = v.open_tamper_reports.first_mut() {
            report.1 = d;
        }
        variants.push(("open_tamper_reports (replaced)", v));
        let mut v = base.clone();
        if let Some(first) = v.seen_restorations.iter().next().copied() {
            v.seen_restorations.remove(&first);
        }
        v.seen_restorations.insert(d);
        variants.push(("seen_restorations (replaced)", v));
        let mut v = base.clone();
        if let Some(first) = v.seen_lineage_digests.iter().next().copied() {
            v.seen_lineage_digests.remove(&first);
        }
        v.seen_lineage_digests.insert(d);
        variants.push(("seen_lineage_digests (replaced)", v));

        // Insertions.
        let mut v = base.clone();
        v.open_domains.insert("cam-x".to_owned());
        variants.push(("open_domains", v));
        let mut v = base.clone();
        v.open_tamper_roots.push(d);
        variants.push(("open_tamper_roots", v));
        let mut v = base.clone();
        v.restorations.push(("cam-x".to_owned(), d));
        variants.push(("restorations", v));
        let mut v = base.clone();
        v.open_tamper_records.push(TamperRecord {
            failure_domain: "cam-x".to_owned(),
            identity_digest: None,
            digest: d,
            revision: 1,
            interval: None,
        });
        variants.push(("open_tamper_records", v));
        let mut v = base.clone();
        v.open_tamper_reports.push(("cam-x".to_owned(), d));
        variants.push(("open_tamper_reports", v));
        let mut v = base.clone();
        v.seen_restorations.insert(d);
        variants.push(("seen_restorations", v));
        let mut v = base.clone();
        v.seen_lineage_digests.insert(d);
        variants.push(("seen_lineage_digests", v));
        for (field, variant) in &variants {
            assert_ne!(
                variant.canonical_digest(),
                base.canonical_digest(),
                "canonical_digest ignores {field}"
            );
        }
        Ok(())
    }
}
