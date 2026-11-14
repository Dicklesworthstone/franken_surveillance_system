#![forbid(unsafe_code)]

use super::*;
use fss_core::{
    CaptureInterval, DecisionPath, EventEvidence, EventId, EventKind, EventState, EvidenceClass,
    ProbabilityInterval, TimestampNs,
};
use fss_fusion::Decision;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn source() -> TestResult<EventHypothesis> {
    let evidence = [
        ("camera:east", EvidenceEdgeRelation::Supports),
        ("camera:west", EvidenceEdgeRelation::Supports),
        ("camera:uncertain", EvidenceEdgeRelation::SensorTamper),
    ]
    .into_iter()
    .map(|(domain, relation)| EventEvidence {
        digest: ContentDigest::sha256(format!("evidence:{domain}").as_bytes()),
        class: EvidenceClass::Derived,
        failure_domain: domain.to_owned(),
        supports: relation.required_supports_flag(),
        relation,
        capsule_digest: Some(ContentDigest::sha256(format!("capsule:{domain}").as_bytes())),
        identity_digest: None,
    })
    .collect();
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(),
        event_id: EventId::parse("event:source-loss-contract")?,
        revision: 1,
        supersedes: None,
        state: EventState::Hypothesized,
        kind: EventKind::PerimeterBreach,
        interval: CaptureInterval::new(TimestampNs(1_000), TimestampNs(2_000))?,
        uncertainty_reason: Some("capture time remains uncertain".to_owned()),
        zone_ids: vec!["zone:east".to_owned()],
        track_ids: vec![],
        probability: ProbabilityInterval::with_calibration(
            0.1,
            0.9,
            ContentDigest::sha256(b"original-event-calibration"),
        )?,
        evidence,
        model_receipts: vec![ContentDigest::sha256(b"original-model-receipt")],
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(b"original-event-policy"),
            fingerprint: ContentDigest::sha256(b"original-event-decision"),
            abstained: true,
            abstention_reason: Some("unresolved source integrity".to_owned()),
        },
    };
    event.verify()?;
    Ok(event)
}

fn calibration_fixture() -> TestResult<ScoreCalibration> {
    Ok(ScoreCalibration::from_counts(
        "caller-test-generation",
        &[0, 800_000],
        &[(100, 9_900), (9_900, 100)],
    )?)
}

fn root() -> ContentDigest {
    ContentDigest::sha256(b"immutable-test-publication")
}

fn request_json(
    event: &EventHypothesis,
    calibration: &ScoreCalibration,
    scores: &str,
    without: &[&str],
) -> String {
    object(&[
        ("schema", string(EVENT_COUNTERFACTUAL_REQUEST_SCHEMA)),
        ("event_revision_digest", string(&event.revision_digest().to_text())),
        ("without_domains", strings(without)),
        ("score_calibration", calibration_json(calibration)),
        ("domain_scores_ppm", scores.to_owned()),
    ])
}

fn standard_request(event: &EventHypothesis) -> TestResult<EventCounterfactualRequest> {
    Ok(EventCounterfactualRequest::parse(&request_json(
        event,
        &calibration_fixture()?,
        r#"{"camera:east":900000,"camera:west":900000}"#,
        &["camera:east"],
    ))?)
}

#[test]
fn loss_recomputes_both_queries_without_upgrading_coverage_or_independence() -> TestResult {
    let event = source()?;
    let original = event.to_canonical_json();
    let request = standard_request(&event)?;
    let result = request.compute_event(&event, root())?;
    let baseline = result.ablation().original_query();
    let alternative = result.ablation().counterfactual_query();
    assert_eq!(baseline.evidence.len(), 2);
    assert_eq!(alternative.evidence.len(), 2);
    assert!(matches!(baseline.coverage, Coverage::Gap { .. }));
    assert_eq!(baseline.coverage, alternative.coverage);
    assert_eq!(baseline.prior, alternative.prior);
    assert_eq!(baseline.policy, alternative.policy);
    assert_eq!(baseline.severity, alternative.severity);
    assert_eq!(baseline.looks, 1);
    assert_eq!(alternative.now_ns, 0);
    assert!(baseline.opportunities.is_empty() && alternative.probes.is_empty());

    let lost = format!("edge:0:{}", event.evidence[0].digest);
    assert_eq!(result.ablation().unavailable_evidence(), [lost.clone()]);
    for (before, after) in baseline.evidence.iter().zip(&alternative.evidence) {
        assert_eq!(before.id, after.id);
        assert_eq!(before.calibration, after.calibration);
        assert_eq!(before.failure_domains, after.failure_domains);
        assert_eq!(before.sensor, SYNTHETIC_GROUP);
        assert!(before.failure_domains.contains(&format!(
            "calibration:{}",
            request.calibration.digest
        )));
        assert_eq!(before.observability, Observability::Observed);
        if before.id == lost {
            assert!(matches!(after.observability, Observability::NotObservable { .. }));
        } else {
            assert_eq!(after.observability, Observability::Observed);
        }
    }
    assert_eq!(result.ablation().baseline().clusters.len(), 1);
    assert_eq!(result.ablation().outcome().clusters.len(), 1);
    assert!(result.ablation().baseline().supporting_clusters <= 1);
    assert!(!matches!(
        result.ablation().baseline().decision,
        Decision::Alert | Decision::AlertDegradedCoverage | Decision::AlertSingleDomainUnconfirmed
    ));
    assert_eq!(event.to_canonical_json(), original);

    let json = parse(&result.to_json()?)?;
    let fields = json.object().ok_or("result object")?;
    assert_eq!(fields.get("source_event"), Some(&parse(&original)?));
    assert_eq!(fields.get("request"), Some(&parse(&request.canonical_request_json())?));
    for key in [
        "source_custody_verified",
        "historical_decision_replayed",
        "physical_coverage_certified",
        "event_policy_changed",
        "published",
        "effect_authority",
    ] {
        assert_eq!(fields.get(key), Some(&Value::Bool(false)));
    }
    assert_eq!(result.request_digest(), request.request_digest());
    assert_eq!(
        fields.get("source_publication_root").and_then(Value::text),
        Some(root().to_text().as_str())
    );
    Ok(())
}

#[test]
fn complete_source_loss_is_missingness_and_never_physical_absence() -> TestResult {
    let event = source()?;
    let request = EventCounterfactualRequest::parse(&request_json(
        &event,
        &calibration_fixture()?,
        r#"{"camera:east":100000,"camera:west":100000}"#,
        &["camera:east", "camera:west"],
    ))?;
    let result = request.compute_event(&event, root())?;
    assert_eq!(result.ablation().unavailable_evidence().len(), 2);
    assert!(result.ablation().outcome().clusters.is_empty());
    assert_eq!(result.ablation().outcome().excluded.len(), 2);
    assert_eq!(result.ablation().outcome().knowledge_state, "not_observable");
    assert_ne!(result.ablation().outcome().decision, Decision::Reject);
    assert_ne!(result.ablation().baseline().decision, Decision::Reject);
    assert!(matches!(
        result.ablation().counterfactual_query().coverage,
        Coverage::Gap { .. }
    ));
    Ok(())
}

#[test]
fn exact_raw_scores_bind_identity_even_when_the_numerical_bin_is_unchanged() -> TestResult {
    let event = source()?;
    let calibration = calibration_fixture()?;
    assert_eq!(calibration.calibrate(900_000), calibration.calibrate(850_000));
    let first = standard_request(&event)?;
    let second = EventCounterfactualRequest::parse(&request_json(
        &event,
        &calibration,
        r#"{"camera:east":850000,"camera:west":900000}"#,
        &["camera:east"],
    ))?;
    let before = first.compute_event(&event, root())?;
    let after = second.compute_event(&event, root())?;
    assert_eq!(before.ablation().digest(), after.ablation().digest());
    assert_ne!(first.request_digest(), second.request_digest());
    assert_ne!(before.digest(), after.digest());
    assert_ne!(before.receipt().receipt_digest(), after.receipt().receipt_digest());
    assert_ne!(before.to_json()?, after.to_json()?);
    Ok(())
}

#[test]
fn map_and_simultaneous_selector_order_have_one_canonical_request() -> TestResult {
    let event = source()?;
    let calibration = calibration_fixture()?;
    let first = EventCounterfactualRequest::parse(&request_json(
        &event,
        &calibration,
        r#"{"camera:east":900000,"camera:west":100000}"#,
        &["camera:east", "camera:west"],
    ))?;
    let second = EventCounterfactualRequest::parse(&request_json(
        &event,
        &calibration,
        r#"{"camera:west":100000,"camera:east":900000}"#,
        &["camera:west", "camera:east"],
    ))?;
    assert_eq!(first, second);
    assert_eq!(first.canonical_request_json(), second.canonical_request_json());
    assert_eq!(
        first.compute_event(&event, root())?.to_json()?,
        second.compute_event(&event, root())?.to_json()?
    );
    assert_eq!(
        EventCounterfactualRequest::parse(&first.canonical_request_json())?,
        first
    );
    Ok(())
}

#[test]
fn scores_must_exactly_cover_contributing_domains_without_guessing() -> TestResult {
    let event = source()?;
    let calibration = calibration_fixture()?;
    for mapping in [
        r#"{"camera:east":900000}"#,
        r#"{"camera:east":900000,"camera:west":900000,"camera:unused":900000}"#,
        r#"{"camera:east":900000,"camera:west":900000,"camera:uncertain":900000}"#,
        r#"{"0":900000,"camera:east":900000}"#,
    ] {
        let request = EventCounterfactualRequest::parse(&request_json(
            &event,
            &calibration,
            mapping,
            &["camera:east"],
        ))?;
        assert!(matches!(
            request.compute_event(&event, root()),
            Err(EventCounterfactualError::InvalidRequest(_))
        ));
    }
    let mut contradiction = event.clone();
    contradiction.evidence[1].relation = EvidenceEdgeRelation::Contradicts;
    contradiction.evidence[1].supports = false;
    contradiction.verify()?;
    let request = standard_request(&contradiction)?;
    let result = request.compute_event(&contradiction, root())?;
    assert_eq!(result.ablation().original_query().evidence.len(), 2);
    assert_eq!(result.source.evidence[1].relation, EvidenceEdgeRelation::Contradicts);
    assert_eq!(result.source.evidence[2].relation, EvidenceEdgeRelation::SensorTamper);
    Ok(())
}

#[test]
fn stale_revision_invalid_source_and_unbound_publication_are_refused() -> TestResult {
    let event = source()?;
    let request = standard_request(&event)?;
    let mut changed = event.clone();
    changed.uncertainty_reason = Some("different retained evidence".to_owned());
    assert!(matches!(
        request.compute_event(&changed, root()),
        Err(EventCounterfactualError::StaleRevision)
    ));
    let mut invalid_event = event.clone();
    invalid_event.evidence[0].supports = false;
    assert!(matches!(
        request.compute_event(&invalid_event, root()),
        Err(EventCounterfactualError::InvalidEvent)
    ));
    assert!(matches!(
        request.compute_event(&event, ContentDigest::new(DigestAlgorithm::Sha256, [0; 32])),
        Err(EventCounterfactualError::InvalidEvent)
    ));
    let first = request.compute_event(&event, root())?;
    let second = request.compute_event(&event, ContentDigest::sha256(b"another-publication"))?;
    assert_eq!(first.ablation().digest(), second.ablation().digest());
    assert_ne!(first.digest(), second.digest());
    assert_ne!(first.receipt().receipt_digest(), second.receipt().receipt_digest());
    Ok(())
}

#[test]
fn ambiguous_synthetic_common_cause_names_cannot_select_unrelated_rows() -> TestResult {
    let calibration = calibration_fixture()?;
    for collision in [
        format!("sensor:{SYNTHETIC_GROUP}"),
        format!("calibration:{}", calibration.digest),
    ] {
        let mut event = source()?;
        event.evidence[0].failure_domain = collision.clone();
        event.verify()?;
        let mapping = scores_json(&BTreeMap::from([
            (collision.clone(), 900_000),
            ("camera:west".to_owned(), 900_000),
        ]));
        let request = EventCounterfactualRequest::parse(&request_json(
            &event,
            &calibration,
            &mapping,
            &[&collision],
        ))?;
        assert!(matches!(
            request.compute_event(&event, root()),
            Err(EventCounterfactualError::InvalidRequest(_))
        ));
    }
    Ok(())
}

#[test]
fn duplicate_unknown_empty_and_implicit_selectors_are_refused() -> TestResult {
    let event = source()?;
    let calibration = calibration_fixture()?;
    for selectors in [
        vec![],
        vec!["camera:east", "camera:east"],
        vec!["camera:unknown"],
        vec!["event-evidence-projection"],
        vec![""],
    ] {
        assert!(matches!(
            EventCounterfactualRequest::parse(&request_json(
                &event,
                &calibration,
                r#"{"camera:east":900000,"camera:west":900000}"#,
                &selectors,
            )),
            Err(EventCounterfactualError::InvalidRequest(_))
        ));
    }
    Ok(())
}

#[test]
fn closed_request_refuses_ambiguous_numeric_inputs_aliases_and_paths() -> TestResult {
    let event = source()?;
    let calibration = calibration_fixture()?;
    for mapping in [
        r#"{"camera:east":"900000","camera:west":900000}"#,
        r#"{"camera:east":9e5,"camera:west":900000}"#,
        r#"{"camera:east":900000.0,"camera:west":900000}"#,
        r#"{"camera:east":1000001,"camera:west":900000}"#,
        r#"{"camera:east":-1,"camera:west":900000}"#,
        r#"{"camera:east":900000,"camera:east":900000,"camera:west":900000}"#,
        r#"{"camera:east":900000,"\u0000":900000}"#,
    ] {
        assert!(EventCounterfactualRequest::parse(&request_json(
            &event,
            &calibration,
            mapping,
            &["camera:east"],
        )).is_err());
    }
    let valid = request_json(
        &event,
        &calibration,
        r#"{"camera:east":900000,"camera:west":900000}"#,
        &["camera:east"],
    );
    for extra in [
        r#""path":"/ungranted/file","#,
        r#""camera_scores_ppm":{"camera:east":900000},"#,
        r#""unknown":true,"#,
        r#""schema":"fss.event_counterfactual_request.v1","#,
    ] {
        let changed = valid.replacen('{', &format!("{{{extra}"), 1);
        assert!(EventCounterfactualRequest::parse(&changed).is_err());
    }
    for policy in ["+1000,0,-1000", "1000,0,-0", "0,1000,-1000", "1000, 0,-1000", "1000,0"] {
        let changed = valid.replacen('{', &format!("{{\"fusion_policy\":{},", string(policy)), 1);
        assert!(EventCounterfactualRequest::parse(&changed).is_err());
    }
    Ok(())
}

#[test]
fn native_calibration_summaries_are_recomputed_instead_of_trusted() -> TestResult {
    let event = source()?;
    let calibration = calibration_fixture()?;
    let valid = request_json(
        &event,
        &calibration,
        r#"{"camera:east":900000,"camera:west":900000}"#,
        &["camera:east"],
    );
    let changes = [
        valid.replacen("\"true_positives\":10000", "\"true_positives\":10001", 1),
        valid.replacen(
            &format!("\"hi_ppm\":{}", calibration.bins[0].hi_ppm),
            "\"hi_ppm\":0",
            1,
        ),
        valid.replacen(
            &format!("\"prior_log_odds_millibans\":[{},{}]", calibration.prior.lo(), calibration.prior.hi()),
            "\"prior_log_odds_millibans\":[0,0]",
            1,
        ),
        valid.replacen(
            &format!("\"llr_millibans\":[{},{}]", calibration.bins[0].llr.lo(), calibration.bins[0].llr.hi()),
            "\"llr_millibans\":[0,0]",
            1,
        ),
        valid.replacen(INTERVAL, "caller_point_estimate", 1),
        valid.replacen(
            "\"score_calibration\":{",
            "\"score_calibration\":{\"unverified_posterior\":1000000,",
            1,
        ),
        valid.replacen(
            &calibration.digest.to_text(),
            &ContentDigest::sha256(b"not-these-counts").to_text(),
            1,
        ),
    ];
    for changed in changes {
        assert_ne!(changed, valid, "regression must change an input field");
        assert!(EventCounterfactualRequest::parse(&changed).is_err());
    }
    let compact_bins: Vec<_> = calibration.bins.iter().map(|bin| object(&[
        ("lo_ppm", bin.lo_ppm.to_string()),
        ("true_positives", bin.positives.to_string()),
        ("false_positives", bin.negatives.to_string()),
    ])).collect();
    let compact = object(&[
        ("schema", string("fss.score_calibration.v1")),
        ("generation", string(&calibration.generation)),
        ("digest", string(&calibration.digest.to_text())),
        ("bins", array(&compact_bins)),
    ]);
    let counts_only = valid.replace(&calibration_json(&calibration), &compact);
    assert_eq!(
        EventCounterfactualRequest::parse(&counts_only)?,
        EventCounterfactualRequest::parse(&valid)?
    );
    Ok(())
}

#[test]
fn request_and_complete_result_bounds_refuse_without_truncated_fallback() -> TestResult {
    assert_eq!(
        EventCounterfactualRequest::parse(&" ".repeat(MAX_COUNTERFACTUAL_REQUEST_BYTES + 1)),
        Err(EventCounterfactualError::Limit)
    );
    let mut event = source()?;
    let domain = format!("camera:{}", "x".repeat(120));
    let template = event.evidence[0].clone();
    event.evidence = (0..256).map(|index| {
        let mut edge = template.clone();
        edge.failure_domain = domain.clone();
        edge.digest = ContentDigest::sha256(format!("bounded-edge:{index}").as_bytes());
        edge.identity_digest = Some(ContentDigest::sha256(format!("identity:{index}").as_bytes()));
        edge
    }).collect();
    event.verify()?;
    let scores = scores_json(&BTreeMap::from([(domain.clone(), 900_000)]));
    let request = EventCounterfactualRequest::parse(&request_json(
        &event,
        &calibration_fixture()?,
        &scores,
        &[&domain],
    ))?;
    assert!(matches!(
        request.compute_event(&event, root()),
        Err(EventCounterfactualError::Limit)
    ));
    Ok(())
}
