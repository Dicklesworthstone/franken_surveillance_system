#![forbid(unsafe_code)]
//! Integration and contract tests for event revision and evidence graph schemas (FSS-007).
//!
//! Verifies:
//! - Canonical event revision binary (FSSE v1) and JSON round-trips (bit-identical).
//! - Canonical evidence graph binary (FSSG v1) and JSON round-trips (bit-identical).
//! - Cross-codec round trips.
//! - Revisions are immutable: genesis revision 1 cannot supersede; correction revision > 1 MUST supersede.
//! - Graph edges reference capsule and identity digests with failure domain isolation.
//! - Corroboration failure domain enforcement (>= 2 distinct failure domains).
//! - Evidence required after initial hypothesis.
//! - Typed decode errors for truncation, unknown version, trailing bytes, schema mismatch,
//!   and invalid Unicode escapes without default-on-error.
//! - Hard size bounds tested at exactly bound and bound + 1.
//! - Graph query methods: supporting, contradicting, failure domains, referenced digests.

use std::error::Error;

use fss_core::{
    CaptureInterval, ContentDigest, ContractError, DecisionPath, EVENT_HYPOTHESIS_MAGIC,
    EVENT_HYPOTHESIS_SCHEMA, EVENT_HYPOTHESIS_VERSION_1, EVIDENCE_GRAPH_MAGIC,
    EVIDENCE_GRAPH_SCHEMA, EVIDENCE_GRAPH_VERSION_1, EventDecodeError, EventEvidence,
    EventHypothesis, EventId, EventKind, EventState, EvidenceClass, EvidenceEdgeRelation,
    EvidenceGraph, EvidenceNode, EvidenceNodeKind, MAX_ABSTENTION_REASON_LEN, MAX_EDGES_COUNT,
    MAX_EVENT_ID_LEN, MAX_EVIDENCE_COUNT, MAX_FAILURE_DOMAIN_LEN, MAX_GRAPH_ID_LEN,
    MAX_MODEL_RECEIPTS_COUNT, MAX_NODE_LABEL_LEN, MAX_NODES_COUNT, MAX_TRACK_ID_LEN,
    MAX_TRACKS_COUNT, MAX_UNCERTAINTY_REASON_LEN, MAX_ZONE_ID_LEN, MAX_ZONES_COUNT,
    ProbabilityInterval, TimestampNs,
};

fn sample_interval() -> Result<CaptureInterval, ContractError> {
    CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))
}

fn sample_evidence(cam_id: &str, supports: bool) -> EventEvidence {
    let digest = ContentDigest::sha256(format!("evidence:{cam_id}").as_bytes());
    let capsule_digest = Some(ContentDigest::sha256(
        format!("capsule:{cam_id}").as_bytes(),
    ));
    let identity_digest = Some(ContentDigest::sha256(
        format!("identity:{cam_id}").as_bytes(),
    ));
    EventEvidence {
        digest,
        class: EvidenceClass::Derived,
        failure_domain: format!("domain:{cam_id}"),
        supports,
        relation: if supports {
            EvidenceEdgeRelation::Supports
        } else {
            EvidenceEdgeRelation::Contradicts
        },
        capsule_digest,
        identity_digest,
    }
}

fn sample_genesis_event() -> Result<EventHypothesis, Box<dyn Error>> {
    let event_id = EventId::parse("event:perimeter-east-001")?;
    let interval = sample_interval()?;
    let probability = ProbabilityInterval::with_calibration(
        0.85,
        0.98,
        ContentDigest::sha256(b"calibration:gen:1"),
    )?;
    let evidence = vec![
        sample_evidence("cam-east-1", true),
        sample_evidence("radar-east-1", true),
    ];
    let model_receipts = vec![
        ContentDigest::sha256(b"receipt:model:yolo-pose-v1"),
        ContentDigest::sha256(b"receipt:model:radar-tracker-v1"),
    ];
    let decision_path = DecisionPath {
        policy_generation: ContentDigest::sha256(b"policy:gen:1"),
        fingerprint: ContentDigest::sha256(b"policy:boundary-defense-v1"),
        abstained: false,
        abstention_reason: None,
    };

    let event = EventHypothesis {
        schema: EVENT_HYPOTHESIS_SCHEMA.to_string(),
        event_id,
        revision: 1,
        supersedes: None,
        state: EventState::Corroborated,
        kind: EventKind::PerimeterBreach,
        interval,
        uncertainty_reason: Some("calibrated thermal variance < 5ms".to_string()),
        zone_ids: vec!["zone:east-fence".to_string(), "zone:gate-4".to_string()],
        track_ids: vec!["track:tgt-1042".to_string()],
        probability,
        evidence,
        model_receipts,
        decision_path,
    };
    event.verify()?;
    Ok(event)
}

fn sample_evidence_graph() -> Result<EvidenceGraph, Box<dyn Error>> {
    let event = sample_genesis_event()?;
    let root_digest = event.revision_digest();

    let node_ev_cam = EvidenceNode {
        digest: ContentDigest::sha256(b"evidence:cam-east-1"),
        kind: EvidenceNodeKind::Observation,
        label: "Camera East 1 Observation".to_string(),
        failure_domain: "domain:cam-east-1".to_string(),
    };
    let node_cap_cam = EvidenceNode {
        digest: ContentDigest::sha256(b"capsule:cam-east-1"),
        kind: EvidenceNodeKind::SensorCapsule,
        label: "Camera East 1 Frame 42".to_string(),
        failure_domain: "domain:cam-east-1".to_string(),
    };
    let node_id_cam = EvidenceNode {
        digest: ContentDigest::sha256(b"identity:cam-east-1"),
        kind: EvidenceNodeKind::SourceIdentity,
        label: "Camera East 1 Identity".to_string(),
        failure_domain: "domain:cam-east-1".to_string(),
    };

    let node_ev_radar = EvidenceNode {
        digest: ContentDigest::sha256(b"evidence:radar-east-1"),
        kind: EvidenceNodeKind::Observation,
        label: "Radar East 1 Observation".to_string(),
        failure_domain: "domain:radar-east-1".to_string(),
    };
    let node_cap_radar = EvidenceNode {
        digest: ContentDigest::sha256(b"capsule:radar-east-1"),
        kind: EvidenceNodeKind::SensorCapsule,
        label: "Radar East 1 Track 42".to_string(),
        failure_domain: "domain:radar-east-1".to_string(),
    };
    let node_id_radar = EvidenceNode {
        digest: ContentDigest::sha256(b"identity:radar-east-1"),
        kind: EvidenceNodeKind::SourceIdentity,
        label: "Radar East 1 Identity".to_string(),
        failure_domain: "domain:radar-east-1".to_string(),
    };

    let node_receipt1 = EvidenceNode {
        digest: ContentDigest::sha256(b"receipt:model:yolo-pose-v1"),
        kind: EvidenceNodeKind::ModelReceipt,
        label: "YOLO Pose Evaluation Receipt".to_string(),
        failure_domain: "domain:model-runner-1".to_string(),
    };

    let graph = EvidenceGraph {
        schema: EVIDENCE_GRAPH_SCHEMA.to_string(),
        graph_id: "graph:east-breach-rev1".to_string(),
        event_id: event.event_id.clone(),
        revision: 1,
        root_digest,
        nodes: vec![
            node_ev_cam,
            node_cap_cam,
            node_id_cam,
            node_ev_radar,
            node_cap_radar,
            node_id_radar,
            node_receipt1,
        ],
        edges: event.evidence.clone(),
    };
    graph.verify()?;
    Ok(graph)
}

#[test]
fn test_event_revision_genesis_roundtrip_binary() -> Result<(), Box<dyn Error>> {
    let event = sample_genesis_event()?;
    let encoded = event.to_versioned_bytes()?;

    assert!(encoded.len() >= 6);
    assert_eq!(&encoded[0..4], &EVENT_HYPOTHESIS_MAGIC);
    assert_eq!(
        u16::from_be_bytes([encoded[4], encoded[5]]),
        EVENT_HYPOTHESIS_VERSION_1
    );

    let decoded = EventHypothesis::from_versioned_bytes(&encoded)?;
    assert_eq!(event, decoded);

    let reencoded = decoded.to_versioned_bytes()?;
    assert_eq!(encoded, reencoded);
    Ok(())
}

#[test]
fn test_event_revision_canonical_json_roundtrip() -> Result<(), Box<dyn Error>> {
    let event = sample_genesis_event()?;
    let json = event.to_canonical_json();

    let decoded = EventHypothesis::from_json(&json)?;
    assert_eq!(event, decoded);

    let json2 = decoded.to_canonical_json();
    assert_eq!(json, json2);
    Ok(())
}

#[test]
fn test_event_revision_cross_codec_roundtrip() -> Result<(), Box<dyn Error>> {
    let event = sample_genesis_event()?;
    let bytes = event.to_versioned_bytes()?;
    let from_bytes = EventHypothesis::from_versioned_bytes(&bytes)?;

    let json = from_bytes.to_canonical_json();
    let from_json = EventHypothesis::from_json(&json)?;

    let re_bytes = from_json.to_versioned_bytes()?;
    assert_eq!(bytes, re_bytes);
    Ok(())
}

#[test]
fn test_correction_supersedes_prior_revision() -> Result<(), Box<dyn Error>> {
    let genesis = sample_genesis_event()?;
    let prior_digest = genesis.revision_digest();

    let mut correction = genesis.clone();
    correction.revision = 2;
    correction.supersedes = Some(prior_digest);
    correction.state = EventState::Adjudicated;
    correction.verify()?;

    let bytes = correction.to_versioned_bytes()?;
    let decoded = EventHypothesis::from_versioned_bytes(&bytes)?;
    assert_eq!(decoded.revision, 2);
    assert_eq!(decoded.supersedes, Some(prior_digest));
    assert_eq!(decoded.state, EventState::Adjudicated);

    let json = decoded.to_canonical_json();
    let from_json = EventHypothesis::from_json(&json)?;
    assert_eq!(decoded, from_json);
    Ok(())
}

#[test]
fn test_genesis_with_supersedes_rejected() -> Result<(), Box<dyn Error>> {
    let mut event = sample_genesis_event()?;
    event.revision = 1;
    event.supersedes = Some(ContentDigest::sha256(b"bogus-prior"));
    let Err(err) = event.verify() else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::Contradiction {
            field: "supersedes",
            ..
        }
    ));
    Ok(())
}

#[test]
fn test_correction_without_supersedes_rejected() -> Result<(), Box<dyn Error>> {
    let mut event = sample_genesis_event()?;
    event.revision = 2;
    event.supersedes = None;
    let Err(err) = event.verify() else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::Contradiction {
            field: "supersedes",
            ..
        }
    ));
    Ok(())
}

#[test]
fn test_revision_zero_rejected() -> Result<(), Box<dyn Error>> {
    let mut event = sample_genesis_event()?;
    event.revision = 0;
    event.supersedes = None;
    let Err(err) = event.verify() else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::OutOfRange {
            field: "revision",
            ..
        }
    ));
    Ok(())
}

#[test]
fn test_corroboration_requires_two_failure_domains() -> Result<(), Box<dyn Error>> {
    let mut event = sample_genesis_event()?;
    event.state = EventState::Corroborated;
    event.evidence = vec![
        sample_evidence("cam-east-1", true),
        sample_evidence("cam-east-1", true),
    ];
    assert_eq!(event.validate(), Err(ContractError::CorroborationRequired));
    let Err(err) = event.verify() else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::Contract(ContractError::CorroborationRequired)
    ));

    // Positive case: two distinct failure domains pass
    event.evidence = vec![
        sample_evidence("cam-east-1", true),
        sample_evidence("cam-west-1", true),
    ];
    assert_eq!(event.validate(), Ok(()));
    assert!(event.verify().is_ok());

    Ok(())
}

#[test]
fn test_evidence_required_after_hypothesis() -> Result<(), Box<dyn Error>> {
    let mut event = sample_genesis_event()?;
    event.state = EventState::Witnessed;
    event.evidence = Vec::new();
    let Err(err) = event.verify() else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::Contract(ContractError::EvidenceRequired)
    ));

    event.state = EventState::Hypothesized;
    assert!(event.verify().is_ok());
    Ok(())
}

#[test]
fn test_graph_edges_reference_capsule_and_identity_digests() -> Result<(), Box<dyn Error>> {
    let graph = sample_evidence_graph()?;
    assert_eq!(graph.edges.len(), 2);
    for edge in &graph.edges {
        assert!(edge.capsule_digest.is_some());
        assert!(edge.identity_digest.is_some());
    }

    let capsules = graph.referenced_capsules();
    assert_eq!(capsules.len(), 2);

    let identities = graph.referenced_identities();
    assert_eq!(identities.len(), 2);

    let domains = graph.failure_domains();
    assert!(domains.contains("domain:cam-east-1"));
    assert!(domains.contains("domain:radar-east-1"));
    assert!(domains.contains("domain:model-runner-1"));
    Ok(())
}

#[test]
fn test_evidence_graph_roundtrip_binary() -> Result<(), Box<dyn Error>> {
    let graph = sample_evidence_graph()?;
    let bytes = graph.to_versioned_bytes()?;

    assert!(bytes.len() >= 6);
    assert_eq!(&bytes[0..4], &EVIDENCE_GRAPH_MAGIC);
    assert_eq!(
        u16::from_be_bytes([bytes[4], bytes[5]]),
        EVIDENCE_GRAPH_VERSION_1
    );

    let decoded = EvidenceGraph::from_versioned_bytes(&bytes)?;
    assert_eq!(graph, decoded);

    let reencoded = decoded.to_versioned_bytes()?;
    assert_eq!(bytes, reencoded);
    Ok(())
}

#[test]
fn test_evidence_graph_canonical_json_roundtrip() -> Result<(), Box<dyn Error>> {
    let graph = sample_evidence_graph()?;
    let json = graph.to_canonical_json();

    let decoded = EvidenceGraph::from_json(&json)?;
    assert_eq!(graph, decoded);

    let json2 = decoded.to_canonical_json();
    assert_eq!(json, json2);
    Ok(())
}

#[test]
fn test_evidence_graph_queries() -> Result<(), Box<dyn Error>> {
    let mut graph = sample_evidence_graph()?;
    let contr_evidence = sample_evidence("contradictory-sensor", false);
    graph.nodes.push(EvidenceNode {
        digest: contr_evidence.digest,
        kind: EvidenceNodeKind::Observation,
        label: "Contradictory Observation".to_string(),
        failure_domain: "domain:contradictory-sensor".to_string(),
    });
    if let Some(cd) = contr_evidence.capsule_digest {
        graph.nodes.push(EvidenceNode {
            digest: cd,
            kind: EvidenceNodeKind::SensorCapsule,
            label: "Contradictory Capsule".to_string(),
            failure_domain: "domain:contradictory-sensor".to_string(),
        });
    }
    if let Some(id) = contr_evidence.identity_digest {
        graph.nodes.push(EvidenceNode {
            digest: id,
            kind: EvidenceNodeKind::SourceIdentity,
            label: "Contradictory Identity".to_string(),
            failure_domain: "domain:contradictory-sensor".to_string(),
        });
    }
    graph.edges.push(contr_evidence);
    graph.verify()?;

    let supporting: Vec<_> = graph.supporting_edges().collect();
    assert_eq!(supporting.len(), 2);

    let contradicting: Vec<_> = graph.contradicting_edges().collect();
    assert_eq!(contradicting.len(), 1);
    assert!(!contradicting[0].supports);
    Ok(())
}

// ---------------------------------------------------------------------------
// Typed decode errors
// ---------------------------------------------------------------------------

#[test]
fn test_decode_truncated_header() -> Result<(), Box<dyn Error>> {
    let bytes = b"FSS";
    let Err(err) = EventHypothesis::from_versioned_bytes(bytes) else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::Truncated {
            expected_min: 6,
            actual: 3
        }
    ));
    Ok(())
}

#[test]
fn test_decode_invalid_magic() -> Result<(), Box<dyn Error>> {
    let bytes = b"BAD!01payload";
    let Err(err) = EventHypothesis::from_versioned_bytes(bytes) else {
        return Err("expected error".into());
    };
    assert!(matches!(err, EventDecodeError::NonCanonicalEncoding { .. }));
    Ok(())
}

#[test]
fn test_decode_unknown_version() -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&EVENT_HYPOTHESIS_MAGIC);
    bytes.extend_from_slice(&99u16.to_be_bytes());
    bytes.extend_from_slice(b"payload");
    let Err(err) = EventHypothesis::from_versioned_bytes(&bytes) else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::UnknownVersion { version: 99 }
    ));
    Ok(())
}

#[test]
fn test_decode_trailing_bytes() -> Result<(), Box<dyn Error>> {
    let event = sample_genesis_event()?;
    let mut bytes = event.to_versioned_bytes()?;
    bytes.extend_from_slice(b"extra-junk");
    let Err(err) = EventHypothesis::from_versioned_bytes(&bytes) else {
        return Err("expected error".into());
    };
    assert!(matches!(err, EventDecodeError::TrailingBytes { count: 10 }));
    Ok(())
}

#[test]
fn test_decode_schema_mismatch() -> Result<(), Box<dyn Error>> {
    let event = sample_genesis_event()?;
    let mut json = event.to_canonical_json();
    json = json.replace(EVENT_HYPOTHESIS_SCHEMA, "fss.sensor_capsule.v1");
    let Err(err) = EventHypothesis::from_json(&json) else {
        return Err("expected error".into());
    };
    assert!(matches!(err, EventDecodeError::SchemaMismatch { .. }));
    Ok(())
}

#[test]
fn test_decode_invalid_unicode_escape() -> Result<(), Box<dyn Error>> {
    let json = r#"{"schema":"fss.event_hypothesis.v1","eventId":"event:bad\uD800"}"#;
    let Err(err) = EventHypothesis::from_json(json) else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::InvalidUnicodeEscape { codepoint: 0xD800 }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Hard bounds testing at bound and bound + 1
// ---------------------------------------------------------------------------

#[test]
fn test_bound_event_id_len() -> Result<(), Box<dyn Error>> {
    let mut event = sample_genesis_event()?;

    // Bound: exactly MAX_EVENT_ID_LEN (128)
    let id_128 = "e".repeat(MAX_EVENT_ID_LEN);
    event.event_id = EventId::parse(&id_128)?;
    assert!(event.verify().is_ok());

    // Bound + 1: 129 bytes fails EventId::parse
    let id_129 = "e".repeat(MAX_EVENT_ID_LEN + 1);
    assert!(EventId::parse(&id_129).is_err());
    Ok(())
}

#[test]
fn test_bound_graph_id_len() -> Result<(), Box<dyn Error>> {
    let mut graph = sample_evidence_graph()?;

    // Bound: 128
    graph.graph_id = "g".repeat(MAX_GRAPH_ID_LEN);
    assert!(graph.verify().is_ok());

    // Bound + 1: 129
    graph.graph_id = "g".repeat(MAX_GRAPH_ID_LEN + 1);
    let Err(err) = graph.verify() else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::OverLimitLength {
            field: "graphId",
            limit: 128,
            actual: 129
        }
    ));
    Ok(())
}

#[test]
fn test_bound_failure_domain_len() -> Result<(), Box<dyn Error>> {
    let mut event = sample_genesis_event()?;

    // Bound: 128
    event.evidence[0].failure_domain = "d".repeat(MAX_FAILURE_DOMAIN_LEN);
    assert!(event.verify().is_ok());

    // Bound + 1: 129
    event.evidence[0].failure_domain = "d".repeat(MAX_FAILURE_DOMAIN_LEN + 1);
    let Err(err) = event.verify() else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::OverLimitLength {
            field: "evidence.failureDomain",
            limit: 128,
            actual: 129
        }
    ));
    Ok(())
}

#[test]
fn test_bound_node_label_len() -> Result<(), Box<dyn Error>> {
    let mut graph = sample_evidence_graph()?;

    // Bound: 128
    graph.nodes[0].label = "l".repeat(MAX_NODE_LABEL_LEN);
    assert!(graph.verify().is_ok());

    // Bound + 1: 129
    graph.nodes[0].label = "l".repeat(MAX_NODE_LABEL_LEN + 1);
    let Err(err) = graph.verify() else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::OverLimitLength {
            field: "nodes.label",
            limit: 128,
            actual: 129
        }
    ));
    Ok(())
}

#[test]
fn test_bound_zone_id_len() -> Result<(), Box<dyn Error>> {
    let mut event = sample_genesis_event()?;

    // Bound: 64
    event.zone_ids = vec!["z".repeat(MAX_ZONE_ID_LEN)];
    assert!(event.verify().is_ok());

    // Bound + 1: 65
    event.zone_ids = vec!["z".repeat(MAX_ZONE_ID_LEN + 1)];
    let Err(err) = event.verify() else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::OverLimitLength {
            field: "zoneIds[]",
            limit: 64,
            actual: 65
        }
    ));
    Ok(())
}

#[test]
fn test_bound_track_id_len() -> Result<(), Box<dyn Error>> {
    let mut event = sample_genesis_event()?;

    // Bound: 64
    event.track_ids = vec!["t".repeat(MAX_TRACK_ID_LEN)];
    assert!(event.verify().is_ok());

    // Bound + 1: 65
    event.track_ids = vec!["t".repeat(MAX_TRACK_ID_LEN + 1)];
    let Err(err) = event.verify() else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::OverLimitLength {
            field: "trackIds[]",
            limit: 64,
            actual: 65
        }
    ));
    Ok(())
}

#[test]
fn test_bound_uncertainty_reason_len() -> Result<(), Box<dyn Error>> {
    let mut event = sample_genesis_event()?;

    // Bound: 256
    event.uncertainty_reason = Some("u".repeat(MAX_UNCERTAINTY_REASON_LEN));
    assert!(event.verify().is_ok());

    // Bound + 1: 257
    event.uncertainty_reason = Some("u".repeat(MAX_UNCERTAINTY_REASON_LEN + 1));
    let Err(err) = event.verify() else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::OverLimitLength {
            field: "uncertaintyReason",
            limit: 256,
            actual: 257
        }
    ));
    Ok(())
}

#[test]
fn test_bound_zones_count() -> Result<(), Box<dyn Error>> {
    let mut event = sample_genesis_event()?;

    // Bound: 64
    event.zone_ids = (0..MAX_ZONES_COUNT).map(|i| format!("zone:{i}")).collect();
    assert!(event.verify().is_ok());

    // Bound + 1: 65
    event.zone_ids = (0..=MAX_ZONES_COUNT).map(|i| format!("zone:{i}")).collect();
    let Err(err) = event.verify() else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::OverLimitLength {
            field: "zoneIds",
            limit: 64,
            actual: 65
        }
    ));
    Ok(())
}

#[test]
fn test_bound_tracks_count() -> Result<(), Box<dyn Error>> {
    let mut event = sample_genesis_event()?;

    // Bound: 64
    event.track_ids = (0..MAX_TRACKS_COUNT)
        .map(|i| format!("track:{i}"))
        .collect();
    assert!(event.verify().is_ok());

    // Bound + 1: 65
    event.track_ids = (0..=MAX_TRACKS_COUNT)
        .map(|i| format!("track:{i}"))
        .collect();
    let Err(err) = event.verify() else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::OverLimitLength {
            field: "trackIds",
            limit: 64,
            actual: 65
        }
    ));
    Ok(())
}

#[test]
fn test_bound_evidence_count() -> Result<(), Box<dyn Error>> {
    let mut event = sample_genesis_event()?;

    // Bound: 256
    event.evidence = (0..MAX_EVIDENCE_COUNT)
        .map(|i| sample_evidence(&format!("cam-{i}"), true))
        .collect();
    assert!(event.verify().is_ok());

    // Bound + 1: 257
    event.evidence = (0..=MAX_EVIDENCE_COUNT)
        .map(|i| sample_evidence(&format!("cam-{i}"), true))
        .collect();
    let Err(err) = event.verify() else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::OverLimitLength {
            field: "evidence",
            limit: 256,
            actual: 257
        }
    ));
    Ok(())
}

#[test]
fn test_bound_model_receipts_count() -> Result<(), Box<dyn Error>> {
    let mut event = sample_genesis_event()?;

    // Bound: 64
    event.model_receipts = (0..MAX_MODEL_RECEIPTS_COUNT)
        .map(|i| ContentDigest::sha256(format!("receipt:{i}").as_bytes()))
        .collect();
    assert!(event.verify().is_ok());

    // Bound + 1: 65
    event.model_receipts = (0..=MAX_MODEL_RECEIPTS_COUNT)
        .map(|i| ContentDigest::sha256(format!("receipt:{i}").as_bytes()))
        .collect();
    let Err(err) = event.verify() else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::OverLimitLength {
            field: "modelReceipts",
            limit: 64,
            actual: 65
        }
    ));
    Ok(())
}

#[test]
fn test_bound_nodes_count() -> Result<(), Box<dyn Error>> {
    let mut graph = sample_evidence_graph()?;
    graph.edges.clear();

    // Bound: 256
    graph.nodes = (0..MAX_NODES_COUNT)
        .map(|i| EvidenceNode {
            digest: ContentDigest::sha256(format!("node:{i}").as_bytes()),
            kind: EvidenceNodeKind::Observation,
            label: format!("Node {i}"),
            failure_domain: format!("domain:{i}"),
        })
        .collect();
    assert!(graph.verify().is_ok());

    // Bound + 1: 257
    graph.nodes = (0..=MAX_NODES_COUNT)
        .map(|i| EvidenceNode {
            digest: ContentDigest::sha256(format!("node:{i}").as_bytes()),
            kind: EvidenceNodeKind::Observation,
            label: format!("Node {i}"),
            failure_domain: format!("domain:{i}"),
        })
        .collect();
    let Err(err) = graph.verify() else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::OverLimitLength {
            field: "nodes",
            limit: 256,
            actual: 257
        }
    ));
    Ok(())
}

#[test]
fn test_bound_edges_count() -> Result<(), Box<dyn Error>> {
    let mut graph = sample_evidence_graph()?;

    // Bound: 256
    graph.edges = (0..MAX_EDGES_COUNT)
        .map(|_| sample_evidence("cam-east-1", true))
        .collect();
    assert!(graph.verify().is_ok());

    // Bound + 1: 257
    graph.edges = (0..=MAX_EDGES_COUNT)
        .map(|_| sample_evidence("cam-east-1", true))
        .collect();
    let Err(err) = graph.verify() else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::OverLimitLength {
            field: "edges",
            limit: 256,
            actual: 257
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Adversarial review (review-470) regression tests
// ---------------------------------------------------------------------------

#[test]
fn test_failing_surrogate_pair_skips_subsequent_character() -> Result<(), Box<dyn std::error::Error>>
{
    // BUG 3: Off-by-one self.pos += 1 in parse_string skips the character after surrogate pair
    let json = r#"{"schema":"fss.event_hypothesis.v1","eventId":"event:001","revision":1,"supersedes":null,"state":"hypothesized","kind":"unclassified","timeInterval":{"earliestNs":1000,"latestNs":2000,"uncertaintyReason":""},"uncertaintyReason":"\uD83D\uDE00X","zoneIds":[],"trackIds":[],"probability":{"lower":0.5,"upper":0.5,"calibrationGeneration":null},"evidence":[],"modelReceipts":[],"decisionPath":{"abstained":false,"fingerprint":"sha256:0000000000000000000000000000000000000000000000000000000000000000","policyGeneration":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}}"#;
    let ev = EventHypothesis::from_json(json)?;
    assert_eq!(ev.uncertainty_reason.as_deref(), Some("😀X"));
    Ok(())
}

#[test]
fn test_failing_surrogate_pair_at_end_of_string_truncates() -> Result<(), Box<dyn std::error::Error>>
{
    // BUG 3: Off-by-one self.pos += 1 skips the closing quote when surrogate is at end of string
    let json = r#"{"schema":"fss.event_hypothesis.v1","eventId":"event:001","revision":1,"supersedes":null,"state":"hypothesized","kind":"unclassified","timeInterval":{"earliestNs":1000,"latestNs":2000,"uncertaintyReason":""},"uncertaintyReason":"\uD83D\uDE00","zoneIds":[],"trackIds":[],"probability":{"lower":0.5,"upper":0.5,"calibrationGeneration":null},"evidence":[],"modelReceipts":[],"decisionPath":{"abstained":false,"fingerprint":"sha256:0000000000000000000000000000000000000000000000000000000000000000","policyGeneration":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}}"#;
    let res = EventHypothesis::from_json(json);
    assert!(
        res.is_ok(),
        "Expected Ok for valid surrogate pair string, got error: {:?}",
        res.err()
    );
    Ok(())
}

#[test]
fn test_failing_decision_path_schema_object_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    // BUG 2: schemas/event_hypothesis.v1.json mandates decisionPath is an object, but to_canonical_json outputs a string
    let json = r#"{"decisionPath":{"abstained":false,"fingerprint":"sha256:2222222222222222222222222222222222222222222222222222222222222222","policyGeneration":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},"eventId":"event:001","evidence":[],"kind":"unclassified","modelReceipts":[],"probability":{"calibrationGeneration":null,"lower":0.5,"upper":0.5},"revision":1,"schema":"fss.event_hypothesis.v1","state":"hypothesized","supersedes":null,"timeInterval":{"earliestNs":1000,"latestNs":2000,"uncertaintyReason":""},"trackIds":[],"uncertaintyReason":null,"zoneIds":[]}"#;
    let decoded = EventHypothesis::from_json(json)?;
    let re_json = decoded.to_canonical_json();
    assert_eq!(
        json, re_json,
        "Canonical JSON round-trip from schema object must be bit-identical"
    );
    Ok(())
}

#[test]
fn test_failing_non_canonical_duplicate_keys_accepted() {
    // BUG 5: Canonical JSON must reject duplicate keys
    let json = r#"{"schema":"fss.event_hypothesis.v1","eventId":"event:001","revision":1,"revision":2,"supersedes":null,"state":"hypothesized","kind":"unclassified","timeInterval":{"earliestNs":1000,"latestNs":2000,"uncertaintyReason":""},"uncertaintyReason":null,"zoneIds":[],"trackIds":[],"probability":{"lower":0.5,"upper":0.5,"calibrationGeneration":null},"evidence":[],"modelReceipts":[],"decisionPath":{"abstained":false,"fingerprint":"sha256:0000000000000000000000000000000000000000000000000000000000000000","policyGeneration":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}}"#;
    let res = EventHypothesis::from_json(json);
    assert!(
        res.is_err(),
        "Duplicate keys must be rejected as non-canonical, but were accepted"
    );
}

#[test]
fn test_failing_evidence_graph_accepts_supersession_cycle() -> Result<(), Box<dyn std::error::Error>>
{
    // BUG 8: EvidenceGraph accepts cycles in supersession edges
    let mut graph = sample_evidence_graph()?;
    let d1 = ContentDigest::sha256(b"node:1");
    let d2 = ContentDigest::sha256(b"node:2");
    graph.nodes.push(EvidenceNode {
        digest: d1,
        kind: EvidenceNodeKind::EventHypothesis,
        label: "Node 1".to_string(),
        failure_domain: "domain:test".to_string(),
    });
    graph.nodes.push(EvidenceNode {
        digest: d2,
        kind: EvidenceNodeKind::EventHypothesis,
        label: "Node 2".to_string(),
        failure_domain: "domain:test".to_string(),
    });
    graph.edges.push(EventEvidence {
        digest: d1,
        class: EvidenceClass::Derived,
        failure_domain: "domain:test".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::Supersedes,
        capsule_digest: None,
        identity_digest: None,
    });
    graph.edges.push(EventEvidence {
        digest: d2,
        class: EvidenceClass::Derived,
        failure_domain: "domain:test".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::Supersedes,
        capsule_digest: None,
        identity_digest: None,
    });
    assert!(
        graph.verify().is_err(),
        "Supersession cycles in evidence graph must be rejected"
    );
    Ok(())
}

#[test]
fn test_failing_graph_edges_referencing_nonexistent_capsule_and_identity_digests()
-> Result<(), Box<dyn std::error::Error>> {
    // BUG 9: EvidenceGraph verify accepts edges referencing capsule/identity digests that do not exist in graph nodes
    let mut graph = sample_evidence_graph()?;
    graph.nodes.clear();
    graph.edges.push(EventEvidence {
        digest: ContentDigest::sha256(b"dangling-evidence"),
        class: EvidenceClass::Derived,
        failure_domain: "domain:test".to_string(),
        supports: true,
        relation: EvidenceEdgeRelation::Supports,
        capsule_digest: Some(ContentDigest::sha256(b"dangling-capsule")),
        identity_digest: Some(ContentDigest::sha256(b"dangling-identity")),
    });
    assert!(
        graph.verify().is_err(),
        "Dangling edge capsule/identity digest references must be rejected"
    );
    Ok(())
}

#[test]
fn test_failing_untested_bound_max_abstention_reason_len() -> Result<(), Box<dyn std::error::Error>>
{
    // BUG 10: MAX_ABSTENTION_REASON_LEN (512) untested at bound and bound + 1
    let reason_512 = "a".repeat(MAX_ABSTENTION_REASON_LEN);
    let dp = DecisionPath {
        policy_generation: ContentDigest::sha256(b"policy"),
        fingerprint: ContentDigest::sha256(b"fp"),
        abstained: true,
        abstention_reason: Some(reason_512),
    };
    assert!(dp.verify().is_ok());

    let reason_513 = "a".repeat(MAX_ABSTENTION_REASON_LEN + 1);
    let dp_overflow = DecisionPath {
        policy_generation: ContentDigest::sha256(b"policy"),
        fingerprint: ContentDigest::sha256(b"fp"),
        abstained: true,
        abstention_reason: Some(reason_513),
    };
    assert!(
        dp_overflow.verify().is_err(),
        "Bound+1 (513) for abstention reason must fail"
    );
    Ok(())
}

#[test]
fn test_failing_null_on_non_nullable_arrays_accepted() {
    // BUG 6: null silently defaulted on non-nullable array fields
    let json_null_zone = r#"{"schema":"fss.event_hypothesis.v1","eventId":"event:001","revision":1,"supersedes":null,"state":"hypothesized","kind":"unclassified","timeInterval":{"earliestNs":1000,"latestNs":2000,"uncertaintyReason":""},"uncertaintyReason":null,"zoneIds":null,"trackIds":[],"probability":{"lower":0.5,"upper":0.5,"calibrationGeneration":null},"evidence":[],"modelReceipts":[],"decisionPath":{"abstained":false,"fingerprint":"sha256:0000000000000000000000000000000000000000000000000000000000000000","policyGeneration":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}}"#;
    assert!(
        EventHypothesis::from_json(json_null_zone).is_err(),
        "zoneIds: null must be rejected"
    );

    let json_null_track = r#"{"schema":"fss.event_hypothesis.v1","eventId":"event:001","revision":1,"supersedes":null,"state":"hypothesized","kind":"unclassified","timeInterval":{"earliestNs":1000,"latestNs":2000,"uncertaintyReason":""},"uncertaintyReason":null,"zoneIds":[],"trackIds":null,"probability":{"lower":0.5,"upper":0.5,"calibrationGeneration":null},"evidence":[],"modelReceipts":[],"decisionPath":{"abstained":false,"fingerprint":"sha256:0000000000000000000000000000000000000000000000000000000000000000","policyGeneration":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}}"#;
    assert!(
        EventHypothesis::from_json(json_null_track).is_err(),
        "trackIds: null must be rejected"
    );

    let json_null_evidence = r#"{"schema":"fss.event_hypothesis.v1","eventId":"event:001","revision":1,"supersedes":null,"state":"hypothesized","kind":"unclassified","timeInterval":{"earliestNs":1000,"latestNs":2000,"uncertaintyReason":""},"uncertaintyReason":null,"zoneIds":[],"trackIds":[],"probability":{"lower":0.5,"upper":0.5,"calibrationGeneration":null},"evidence":null,"modelReceipts":[],"decisionPath":{"abstained":false,"fingerprint":"sha256:0000000000000000000000000000000000000000000000000000000000000000","policyGeneration":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}}"#;
    assert!(
        EventHypothesis::from_json(json_null_evidence).is_err(),
        "evidence: null must be rejected"
    );
}

#[test]
fn test_uncertainty_reason_contradiction_rejected() {
    // BUG 4: timeInterval.uncertaintyReason and top-level uncertaintyReason contradiction must be rejected
    let json = r#"{"schema":"fss.event_hypothesis.v1","eventId":"event:001","revision":1,"supersedes":null,"state":"hypothesized","kind":"unclassified","timeInterval":{"earliestNs":1000,"latestNs":2000,"uncertaintyReason":"reason_a"},"uncertaintyReason":"reason_b","zoneIds":[],"trackIds":[],"probability":{"lower":0.5,"upper":0.5,"calibrationGeneration":null},"evidence":[],"modelReceipts":[],"decisionPath":{"abstained":false,"fingerprint":"sha256:0000000000000000000000000000000000000000000000000000000000000000","policyGeneration":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}}"#;
    let res = EventHypothesis::from_json(json);
    assert!(matches!(
        res,
        Err(EventDecodeError::Contradiction { field, .. }) if field == "uncertaintyReason"
    ));
}

#[test]
fn test_uncertainty_reason_recovered_from_time_interval() -> Result<(), Box<dyn Error>> {
    // BUG 4: When top-level uncertaintyReason is null, recovered from timeInterval.uncertaintyReason
    let json = r#"{"schema":"fss.event_hypothesis.v1","eventId":"event:001","revision":1,"supersedes":null,"state":"hypothesized","kind":"unclassified","timeInterval":{"earliestNs":1000,"latestNs":2000,"uncertaintyReason":"variance < 5ms"},"uncertaintyReason":null,"zoneIds":[],"trackIds":[],"probability":{"lower":0.5,"upper":0.5,"calibrationGeneration":null},"evidence":[],"modelReceipts":[],"decisionPath":{"abstained":false,"fingerprint":"sha256:0000000000000000000000000000000000000000000000000000000000000000","policyGeneration":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}}"#;
    let ev = EventHypothesis::from_json(json)?;
    assert_eq!(ev.uncertainty_reason.as_deref(), Some("variance < 5ms"));
    Ok(())
}

#[test]
fn test_decision_path_invariants() -> Result<(), Box<dyn Error>> {
    // BUG 10: Invariants on DecisionPath: abstained=false forbids reason; abstained=true requires reason
    let dp_valid_false = DecisionPath {
        policy_generation: ContentDigest::sha256(b"pol"),
        fingerprint: ContentDigest::sha256(b"fp"),
        abstained: false,
        abstention_reason: None,
    };
    assert!(dp_valid_false.verify().is_ok());

    let dp_invalid_false_with_reason = DecisionPath {
        policy_generation: ContentDigest::sha256(b"pol"),
        fingerprint: ContentDigest::sha256(b"fp"),
        abstained: false,
        abstention_reason: Some("unexpected reason".to_string()),
    };
    assert!(matches!(
        dp_invalid_false_with_reason.verify(),
        Err(EventDecodeError::Contradiction { .. })
    ));

    let dp_valid_true = DecisionPath {
        policy_generation: ContentDigest::sha256(b"pol"),
        fingerprint: ContentDigest::sha256(b"fp"),
        abstained: true,
        abstention_reason: Some("sensor occlusion".to_string()),
    };
    assert!(dp_valid_true.verify().is_ok());

    let dp_invalid_true_no_reason = DecisionPath {
        policy_generation: ContentDigest::sha256(b"pol"),
        fingerprint: ContentDigest::sha256(b"fp"),
        abstained: true,
        abstention_reason: None,
    };
    assert!(matches!(
        dp_invalid_true_no_reason.verify(),
        Err(EventDecodeError::Contradiction { .. })
    ));

    // Round trip via from_json and to_canonical_json
    let json = dp_valid_true.to_canonical_json();
    let decoded = DecisionPath::from_json(&json)?;
    assert_eq!(dp_valid_true, decoded);
    assert_eq!(json, decoded.to_canonical_json());
    Ok(())
}

#[test]
fn test_immutable_supersession_transition_and_chain() -> Result<(), Box<dyn Error>> {
    // BUG 7 & 8: supersede() creates valid N+1 revision and verify_chain() validates DAG
    let genesis = sample_genesis_event()?;
    assert_eq!(genesis.revision, 1);
    assert!(genesis.supersedes.is_none());

    let rev2 = genesis.supersede(fss_core::event::EventSupersedeParams {
        state: EventState::Adjudicated,
        kind: EventKind::PerimeterBreach,
        interval: genesis.interval,
        uncertainty_reason: genesis.uncertainty_reason.clone(),
        zone_ids: genesis.zone_ids.clone(),
        track_ids: genesis.track_ids.clone(),
        probability: genesis.probability,
        evidence: genesis.evidence.clone(),
        model_receipts: genesis.model_receipts.clone(),
        decision_path: genesis.decision_path.clone(),
    })?;
    assert_eq!(rev2.revision, 2);
    assert_eq!(rev2.supersedes, Some(genesis.revision_digest()));
    assert_eq!(rev2.state, EventState::Adjudicated);

    // Verify valid 2-node chain
    EventHypothesis::verify_chain(&[genesis.clone(), rev2.clone()])?;

    let rev3 = rev2.supersede(fss_core::event::EventSupersedeParams {
        state: EventState::Resolved,
        kind: EventKind::PerimeterBreach,
        interval: rev2.interval,
        uncertainty_reason: rev2.uncertainty_reason.clone(),
        zone_ids: rev2.zone_ids.clone(),
        track_ids: rev2.track_ids.clone(),
        probability: rev2.probability,
        evidence: rev2.evidence.clone(),
        model_receipts: rev2.model_receipts.clone(),
        decision_path: rev2.decision_path.clone(),
    })?;
    assert_eq!(rev3.revision, 3);
    assert_eq!(rev3.supersedes, Some(rev2.revision_digest()));

    // Verify valid 3-node chain
    EventHypothesis::verify_chain(&[genesis.clone(), rev2.clone(), rev3.clone()])?;

    // Chain validation rejects empty chain
    assert!(EventHypothesis::verify_chain(&[]).is_err());

    // Chain validation rejects revision gap (rev 1 directly to rev 3)
    assert!(EventHypothesis::verify_chain(&[genesis.clone(), rev3.clone()]).is_err());

    // Chain validation rejects wrong predecessor digest
    let mut bad_rev2 = rev2.clone();
    bad_rev2.supersedes = Some(ContentDigest::sha256(b"wrong-predecessor"));
    assert!(EventHypothesis::verify_chain(&[genesis.clone(), bad_rev2]).is_err());

    // Chain validation rejects eventId mismatch
    let mut other_genesis = genesis.clone();
    other_genesis.event_id = EventId::parse("event:other-id")?;
    assert!(EventHypothesis::verify_chain(&[other_genesis, rev2.clone()]).is_err());

    Ok(())
}

#[test]
fn test_graph_edge_individual_digest_validation() -> Result<(), Box<dyn Error>> {
    // BUG 9: capsule_digest and identity_digest must independently be grounded in graph nodes
    let mut graph = sample_evidence_graph()?;

    // Missing capsule digest in nodes
    let edge_missing_cap = EventEvidence {
        digest: ContentDigest::sha256(b"evidence:cam-east-1"), // exists
        class: EvidenceClass::Derived,
        failure_domain: "domain:cam-east-1".to_string(),
        supports: true,
        relation: EvidenceEdgeRelation::Supports,
        capsule_digest: Some(ContentDigest::sha256(b"capsule:unregistered")),
        identity_digest: Some(ContentDigest::sha256(b"identity:cam-east-1")), // exists
    };
    graph.edges.push(edge_missing_cap);
    assert!(matches!(
        graph.verify(),
        Err(EventDecodeError::Contradiction { field, .. }) if field == "edges.capsuleDigest"
    ));
    graph.edges.pop();

    // Missing identity digest in nodes
    let edge_missing_id = EventEvidence {
        digest: ContentDigest::sha256(b"evidence:cam-east-1"), // exists
        class: EvidenceClass::Derived,
        failure_domain: "domain:cam-east-1".to_string(),
        supports: true,
        relation: EvidenceEdgeRelation::Supports,
        capsule_digest: Some(ContentDigest::sha256(b"capsule:cam-east-1")), // exists
        identity_digest: Some(ContentDigest::sha256(b"identity:unregistered")),
    };
    graph.edges.push(edge_missing_id);
    assert!(matches!(
        graph.verify(),
        Err(EventDecodeError::Contradiction { field, .. }) if field == "edges.identityDigest"
    ));
    graph.edges.pop();

    // Self-supersession cycle rejected
    let self_supersede_edge = EventEvidence {
        digest: graph.root_digest, // targets self
        class: EvidenceClass::Derived,
        failure_domain: "domain:test".to_string(),
        supports: false,
        relation: EvidenceEdgeRelation::Supersedes,
        capsule_digest: None,
        identity_digest: None,
    };
    graph.nodes.push(EvidenceNode {
        digest: graph.root_digest,
        kind: EvidenceNodeKind::EventHypothesis,
        label: "Self Root".to_string(),
        failure_domain: "domain:test".to_string(),
    });
    graph.edges.push(self_supersede_edge);
    assert!(matches!(
        graph.verify(),
        Err(EventDecodeError::Contradiction { field, ref detail }) if field == "edges.relation" && detail.contains("cycle detected")
    ));

    Ok(())
}

#[test]
fn test_witnessed_requires_a_supporting_edge() -> Result<(), Box<dyn Error>> {
    let mut event = sample_genesis_event()?;
    event.state = EventState::Witnessed;
    // Contradicting edges alone cannot witness the candidate.
    event.evidence = vec![
        sample_evidence("cam-east-1", false),
        sample_evidence("cam-west-1", false),
    ];
    assert_eq!(
        event.validate(),
        Err(ContractError::SupportingEvidenceRequired)
    );
    let Err(err) = event.verify() else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::Contract(ContractError::SupportingEvidenceRequired)
    ));

    // No evidence at all is a different cause and keeps its own variant.
    event.evidence = Vec::new();
    assert_eq!(event.validate(), Err(ContractError::EvidenceRequired));

    // Positive case: one supporting edge alongside a contradicting one is a valid witness.
    event.evidence = vec![
        sample_evidence("cam-east-1", true),
        sample_evidence("cam-west-1", false),
    ];
    event.verify()?;
    Ok(())
}

#[test]
fn test_supports_flag_must_agree_with_relation_for_every_variant() -> Result<(), Box<dyn Error>> {
    let relations: Vec<EvidenceEdgeRelation> = (0..=u8::MAX)
        .filter_map(|tag| EvidenceEdgeRelation::from_u8(tag).ok())
        .collect();
    if relations.len() != 8 {
        return Err(format!("expected 8 edge relations, found {}", relations.len()).into());
    }
    for relation in relations {
        // Only `Supports` may be flagged supporting; every other relation must be supports=false.
        let admissible_flag = relation == EvidenceEdgeRelation::Supports;
        for supports in [true, false] {
            let mut edge = sample_evidence("cam-east-1", supports);
            edge.relation = relation;
            let verdict = edge.verify();
            if supports == admissible_flag {
                verdict?;
                assert_eq!(
                    edge.counts_as_support(),
                    relation == EvidenceEdgeRelation::Supports,
                    "{relation:?}"
                );
                assert_eq!(
                    edge.counts_as_contradiction(),
                    relation == EvidenceEdgeRelation::Contradicts,
                    "{relation:?}"
                );
            } else {
                assert!(
                    matches!(
                        verdict,
                        Err(EventDecodeError::Contradiction {
                            field: "evidence.supports",
                            ..
                        })
                    ),
                    "{relation:?} with supports={supports}: {verdict:?}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn test_neutral_relations_neither_witness_nor_contradict() -> Result<(), Box<dyn Error>> {
    let mut event = sample_genesis_event()?;
    event.state = EventState::Witnessed;
    for relation in [
        EvidenceEdgeRelation::Invalidates,
        EvidenceEdgeRelation::Explains,
        EvidenceEdgeRelation::DerivedFrom,
    ] {
        // The reviewer's probe: a neutral relation flagged supporting is refused outright.
        let mut edge = sample_evidence("cam-east-1", true);
        edge.relation = relation;
        event.evidence = vec![edge.clone()];
        assert!(
            matches!(
                event.verify(),
                Err(EventDecodeError::Contradiction {
                    field: "evidence.supports",
                    ..
                })
            ),
            "{relation:?}"
        );
        // Correctly flagged it is neutral: it cannot witness the candidate on its own...
        edge.supports = false;
        event.evidence = vec![edge.clone()];
        assert_eq!(
            event.validate(),
            Err(ContractError::SupportingEvidenceRequired),
            "{relation:?}"
        );
        // ...and beside real support it is counted as neither support nor contradiction.
        event.evidence = vec![sample_evidence("cam-west-1", true), edge];
        event.verify()?;
        let analysis = event.analyze_corroboration();
        assert_eq!(analysis.supporting_count, 1, "{relation:?}");
        assert_eq!(analysis.contradicting_count, 0, "{relation:?}");
    }
    Ok(())
}
