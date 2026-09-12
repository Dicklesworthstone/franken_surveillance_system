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
    CaptureInterval, ContentDigest, ContractError, EVENT_HYPOTHESIS_MAGIC, EVENT_HYPOTHESIS_SCHEMA,
    EVENT_HYPOTHESIS_VERSION_1, EVIDENCE_GRAPH_MAGIC, EVIDENCE_GRAPH_SCHEMA,
    EVIDENCE_GRAPH_VERSION_1, EventDecodeError, EventEvidence, EventHypothesis, EventId, EventKind,
    EventState, EvidenceClass, EvidenceEdgeRelation, EvidenceGraph, EvidenceNode, EvidenceNodeKind,
    MAX_EDGES_COUNT, MAX_EVENT_ID_LEN, MAX_EVIDENCE_COUNT, MAX_FAILURE_DOMAIN_LEN,
    MAX_GRAPH_ID_LEN, MAX_MODEL_RECEIPTS_COUNT, MAX_NODE_LABEL_LEN, MAX_NODES_COUNT,
    MAX_TRACK_ID_LEN, MAX_TRACKS_COUNT, MAX_UNCERTAINTY_REASON_LEN, MAX_ZONE_ID_LEN,
    MAX_ZONES_COUNT, ProbabilityInterval, TimestampNs,
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
    let decision_path = ContentDigest::sha256(b"policy:boundary-defense-v1");

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

    let node1 = EvidenceNode {
        digest: ContentDigest::sha256(b"capsule:cam-east-1"),
        kind: EvidenceNodeKind::SensorCapsule,
        label: "Camera East 1 Frame 42".to_string(),
        failure_domain: "domain:cam-east-1".to_string(),
    };
    let node2 = EvidenceNode {
        digest: ContentDigest::sha256(b"capsule:radar-east-1"),
        kind: EvidenceNodeKind::SensorCapsule,
        label: "Radar East 1 Track 42".to_string(),
        failure_domain: "domain:radar-east-1".to_string(),
    };
    let node3 = EvidenceNode {
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
        nodes: vec![node1, node2, node3],
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
    let Err(err) = event.verify() else {
        return Err("expected error".into());
    };
    assert!(matches!(
        err,
        EventDecodeError::Contract(ContractError::CorroborationRequired)
    ));
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
    graph
        .edges
        .push(sample_evidence("contradictory-sensor", false));
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
        .map(|i| sample_evidence(&format!("cam-{i}"), true))
        .collect();
    assert!(graph.verify().is_ok());

    // Bound + 1: 257
    graph.edges = (0..=MAX_EDGES_COUNT)
        .map(|i| sample_evidence(&format!("cam-{i}"), true))
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
