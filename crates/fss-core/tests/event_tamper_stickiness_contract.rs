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
    CaptureInterval, ContentDigest, ContractError, DecisionPath, EVENT_HYPOTHESIS_SCHEMA,
    EventDecodeError, EventEvidence, EventHypothesis, EventId, EventKind, EventState,
    EvidenceClass, EvidenceEdgeRelation, ProbabilityInterval, TimestampNs,
};

fn sample_interval() -> Result<CaptureInterval, ContractError> {
    CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))
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
        identity_digest: None,
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
        identity_digest: None,
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
    let rev1 = genesis.supersede(EventSupersedeParams {
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
    })?;
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
    let bypass_attempt = rev1.supersede(EventSupersedeParams {
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
    });
    assert_eq!(
        bypass_attempt,
        Err(EventDecodeError::Contract(
            ContractError::SensorIntegrityRisk
        ))
    );

    // Supersede rev1 to Indeterminate omitting the tamper edge: unretired tamper remains sticky
    let rev2 = rev1.supersede(EventSupersedeParams {
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
    })?;
    assert!(
        rev2.evidence
            .iter()
            .any(EventEvidence::reports_sensor_tamper)
    );

    // Trying to supersede rev2 to Corroborated still fails
    let bypass_attempt_2 = rev2.supersede(EventSupersedeParams {
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
    });
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
        genesis.interval,
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
        genesis.interval,
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
        genesis.interval,
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
