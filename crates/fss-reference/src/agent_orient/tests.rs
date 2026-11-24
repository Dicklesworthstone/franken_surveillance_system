#![forbid(unsafe_code)]
//! Unit tests for the read-only orientation compiler over real on-disk deployments.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::{
    AffordanceClass, AgentView, BudgetVector, CanonicalEncode, CapsuleId, CaptureInterval,
    ClockBasis, ContentDigest, ContextAuthority, DecisionPath, EventEvidence, EventHypothesis,
    EventId, EventKind, EventState, EvidenceClass, EvidenceEdgeRelation, ExplainQuestion,
    KnowledgeState, LedgerAnchor, OperationId, PrincipalId, ProbabilityInterval, RootAuthoritySpec,
    SensorCapsule, SensorId, SensorSourceBytesSpec, SensorTamperStatus, StreamId, TimestampNs,
};

use super::{
    AFFORDANCE_PLAN, AFFORDANCE_REORIENT, CLAIM_COVERAGE, CLAIM_LEDGER_HEAD, DeploymentReadError,
    MetadataReadBudget, OrientError, OrientLimits, OrientRequest, RECORDED_COVERAGE_PROVENANCE,
    Reader, RetainedEvent, RetainedSourceCoverage, SOURCE_COVERAGE_PROVENANCE,
    WORLD_UNOBSERVED_ACTIVITY, ZoneCoverageState, explain_event, explain_event_with_question,
    orient_deployment, read_deployment,
};
use crate::ingest::source_coverage::{
    RetainedAbsence, RetainedCoverageRefusal, SourceCoverageInput, SourceCoverageRecord,
    build_source_coverage,
};
use crate::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult = Result<(), Box<dyn Error>>;

fn fresh_root(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = std::env::temp_dir().join(format!(
        "fss-agent-orient-unit-{tag}-{}",
        std::process::id()
    ));
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(root)
}

fn empty_deployment(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = fresh_root(tag)?;
    let spec = RootAuthoritySpec {
        trace_id: format!("trace:orient-unit-{tag}"),
        operation_id: OperationId::parse(format!("operation:orient-unit-{tag}"))?,
        principal: format!("operator:orient-unit-{tag}"),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"orient-unit"),
        generation: 1,
    };
    let authority = ContextAuthority::new_root(spec)?;
    let scratch = std::env::temp_dir().join(format!(
        "fss-agent-orient-unit-cx-{tag}-{}",
        std::process::id()
    ));
    let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority, scratch,
    )?);
    drop(ReferenceDeployment::open(&root, "site:orient-unit", &cx)?);
    Ok(root)
}

fn request(view: AgentView) -> Result<OrientRequest, Box<dyn Error>> {
    Ok(OrientRequest {
        view,
        principal: PrincipalId::parse("principal:orient-unit")?,
        budget_tokens: None,
    })
}

#[test]
fn exact_byte_budget_still_checks_empty_and_absent_payloads() -> TestResult {
    let root = fresh_root("exact-byte-budget")?;
    fs::create_dir_all(&root)?;
    fs::write(root.join("payload"), b"one payload")?;
    fs::write(root.join("empty"), b"")?;
    let budget = MetadataReadBudget::new(b"one payload".len(), 3);
    let mut reader = Reader {
        files_read: 0,
        bytes_read: 0,
        budget: Some(budget.clone()),
        cancelled: None,
        pack_catalog: None,
    };
    assert_eq!(
        reader.read_file(&root.join("payload"), 4096)?,
        Some(b"one payload".to_vec()),
    );
    assert_eq!(
        reader.read_file(&root.join("empty"), 4096)?,
        Some(Vec::new()),
    );
    assert_eq!(reader.read_file(&root.join("absent"), 4096)?, None);
    assert_eq!(budget.consumed(), (b"one payload".len() as u64, 3));
    assert_eq!(reader.files_read, 2);
    assert_eq!(reader.bytes_read, b"one payload".len() as u64);
    // Empty and absent reads still exhaust the shared read-attempt ceiling.
    assert!(reader.read_file(&root.join("absent"), 4096).is_err());
    assert_eq!(budget.consumed(), (b"one payload".len() as u64, 3));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn exhausted_byte_budget_never_admits_another_payload_byte() -> TestResult {
    let root = fresh_root("exhausted-byte-budget")?;
    fs::create_dir_all(&root)?;
    fs::write(root.join("payload"), b"x")?;
    let budget = MetadataReadBudget::new(1, 2);
    let mut reader = Reader {
        files_read: 0,
        bytes_read: 0,
        budget: Some(budget.clone()),
        cancelled: None,
        pack_catalog: None,
    };
    assert_eq!(
        reader.read_file(&root.join("payload"), 1)?,
        Some(vec![b'x'])
    );
    assert!(reader.read_file(&root.join("payload"), 1).is_err());
    assert_eq!(budget.consumed(), (1, 2));
    assert_eq!(reader.files_read, 1);
    assert_eq!(reader.bytes_read, 1);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn cancelled_or_failed_reads_cannot_spend_zero_byte_allowances() -> TestResult {
    let budget = MetadataReadBudget::new(1, 4);
    assert_eq!(budget.allowance(1)?, 1);
    budget.charge(1)?;
    let cancelled = || true;
    let mut reader = Reader {
        files_read: 0,
        bytes_read: 0,
        budget: Some(budget.clone()),
        cancelled: Some(&cancelled),
        pack_catalog: None,
    };
    // Cancellation precedes even the stat of this deliberately uncreated path.
    assert!(
        reader
            .read_file(&fresh_root("cancelled-zero-byte-budget")?, 1)
            .is_err()
    );
    assert_eq!(budget.consumed(), (1, 1));
    assert!(budget.ensure_valid().is_err());
    assert!(budget.allowance(0).is_err());
    Ok(())
}

#[test]
fn missing_and_foreign_roots_are_not_deployments() -> TestResult {
    let missing = fresh_root("missing")?;
    assert!(matches!(
        read_deployment(&missing, &OrientLimits::default()),
        Err(DeploymentReadError::NotADeployment { .. })
    ));
    fs::create_dir_all(&missing)?;
    fs::write(missing.join("notes.txt"), b"not a deployment")?;
    assert!(matches!(
        read_deployment(&missing, &OrientLimits::default()),
        Err(DeploymentReadError::NotADeployment { .. })
    ));
    fs::remove_dir_all(&missing)?;
    Ok(())
}

#[test]
fn empty_deployment_orients_to_not_observable_without_invented_facts() -> TestResult {
    let root = empty_deployment("empty")?;
    let limits = OrientLimits::default();
    let snapshot = read_deployment(&root, &limits)?;
    assert!(snapshot.events.is_empty());
    assert_eq!(snapshot.batch_count, 0);
    assert_eq!(snapshot.anchor.commit_sequence, 0);

    let brief = orient_deployment(&snapshot, &request(AgentView::Brief)?, &limits)?;
    let capsule = brief.capsule();
    capsule.validate()?;
    brief.publication.verify()?;
    assert!(
        capsule
            .frame
            .knowledge_cells
            .iter()
            .all(|cell| !cell.claim_id().starts_with("claim:event:"))
    );
    let coverage = capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id() == CLAIM_COVERAGE)
        .ok_or("coverage cell missing")?;
    assert_eq!(coverage.knowledge_state(), KnowledgeState::NotObservable);
    assert!(
        capsule
            .frame
            .knowledge_cells
            .iter()
            .any(|cell| cell.claim_id() == CLAIM_LEDGER_HEAD
                && cell.knowledge_state() == KnowledgeState::Known)
    );
    assert_eq!(brief.epistemic_state, KnowledgeState::NotObservable);
    assert!(
        capsule
            .frame
            .world_envelope
            .adversarial_residuals
            .iter()
            .any(|world| world.world_id == WORLD_UNOBSERVED_ACTIVITY && world.protected)
    );
    assert!(capsule.obligations.is_empty());
    assert!(brief.indeterminate_effects.is_empty());
    let plan = capsule
        .affordances
        .iter()
        .find(|candidate| candidate.affordance_id == AFFORDANCE_PLAN)
        .ok_or("plan affordance missing")?;
    assert_eq!(plan.class, AffordanceClass::Unavailable);
    assert!(!capsule.frame.next.contains(&AFFORDANCE_PLAN.to_owned()));

    // Deterministic: the same committed bytes compile to the same fingerprint.
    let again = orient_deployment(
        &read_deployment(&root, &limits)?,
        &request(AgentView::Brief)?,
        &limits,
    )?;
    assert_eq!(
        again.capsule().decision_fingerprint()?,
        capsule.decision_fingerprint()?
    );
    assert_eq!(
        again.publication.publication_digest,
        brief.publication.publication_digest
    );

    let pulse = orient_deployment(&snapshot, &request(AgentView::Pulse)?, &limits)?;
    assert_eq!(
        pulse
            .capsule()
            .affordances
            .iter()
            .map(|candidate| candidate.affordance_id.as_str())
            .collect::<Vec<_>>(),
        vec![AFFORDANCE_REORIENT]
    );
    assert_eq!(
        pulse.publication.compression_receipt.view_id,
        AgentView::Pulse.id()
    );

    assert!(explain_event(&snapshot, &brief, &EventId::parse("event:none")?)?.is_none());
    fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn inline_budgets_and_request_digests_are_view_bound() -> TestResult {
    assert_eq!(super::inline_event_budget(AgentView::Pulse), 0);
    assert_eq!(super::inline_event_budget(AgentView::Brief), 0);
    assert_eq!(super::inline_event_budget(AgentView::EpistemicMap), 2);
    let root = empty_deployment("digest")?;
    let snapshot = read_deployment(&root, &OrientLimits::default())?;
    let brief = request(AgentView::Brief)?;
    assert_eq!(
        brief.digest_at(&snapshot.anchor),
        brief.digest_at(&snapshot.anchor)
    );
    assert_ne!(
        brief.digest_at(&snapshot.anchor),
        request(AgentView::Pulse)?.digest_at(&snapshot.anchor)
    );
    // An empty deployment compiles nothing out at the source and hydrates nothing.
    let orientation = orient_deployment(&snapshot, &brief, &OrientLimits::default())?;
    assert!(orientation.hydration.is_empty());
    assert!(orientation.headline_event.is_none());
    assert_eq!(orientation.aggregated_world_count, 0);
    assert!(
        orientation
            .publication
            .compression_receipt
            .omitted_classes
            .iter()
            .all(|class| class != super::SOURCE_CLASS_WORLD_DETAIL)
    );
    assert_eq!(
        orientation.request_digest,
        brief.digest_at(&snapshot.anchor)
    );
    assert_eq!(
        orientation.objective.source_request_digest,
        orientation.request_digest.to_text()
    );
    assert_eq!(
        orientation.validity.valid_until,
        snapshot.latest_evidence_time
    );
    fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn too_small_budget_is_refused_not_truncated() -> TestResult {
    let root = empty_deployment("budget")?;
    let limits = OrientLimits::default();
    let snapshot = read_deployment(&root, &limits)?;
    let mut tiny = request(AgentView::Brief)?;
    tiny.budget_tokens = Some(8);
    assert!(matches!(
        orient_deployment(&snapshot, &tiny, &limits),
        Err(OrientError::ContextBudgetExceeded {
            budget_tokens: 8,
            ..
        })
    ));
    assert!(matches!(
        orient_deployment(&snapshot, &request(AgentView::Case)?, &limits),
        Err(OrientError::UnsupportedView(AgentView::Case))
    ));
    fs::remove_dir_all(&root)?;
    Ok(())
}

// --- source-domain coverage (fss-tch7u) ---------------------------------------------------------

const SOURCE_TICKS: u64 = 3;

fn source_seconds(value: u64) -> Result<TimestampNs, Box<dyn Error>> {
    Ok(TimestampNs(
        i128::from(value)
            .checked_mul(1_000_000_000)
            .ok_or("time overflow")?,
    ))
}

/// A real producer record over `[0, SOURCE_TICKS]` s of `cameras` (sensor, failure domain,
/// delivers every tick), anchored at `basis`.
fn source_record(
    basis: &LedgerAnchor,
    cameras: &[(&str, &str, bool)],
) -> Result<SourceCoverageRecord, Box<dyn Error>> {
    let mut capsules = Vec::new();
    for (sensor, domain, delivers) in cameras {
        if !delivers {
            continue;
        }
        for tick in 0..SOURCE_TICKS {
            let packet = format!("packet:{sensor}:{tick}");
            capsules.push((
                (*domain).to_owned(),
                SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
                    capsule_id: CapsuleId::parse(format!("capsule:{sensor}:{tick}"))?,
                    sensor_id: SensorId::parse(format!("sensor:{sensor}"))?,
                    stream_id: StreamId::parse(format!("stream:{sensor}"))?,
                    sequence: tick,
                    capture: CaptureInterval::new(
                        source_seconds(tick)?,
                        source_seconds(tick + 1)?,
                    )?,
                    receive_time: source_seconds(tick + 1)?,
                    clock_basis: ClockBasis::DeviceMonotonic,
                    source: packet.as_bytes(),
                    frame_count: 1,
                    gap_before: false,
                })?,
            ));
        }
    }
    Ok(build_source_coverage(&SourceCoverageInput {
        basis: basis.clone(),
        interval: CaptureInterval::new(source_seconds(0)?, source_seconds(SOURCE_TICKS)?)?,
        negative_predicate: "no_unknown_person_present",
        authorized_domain: cameras
            .iter()
            .map(|(_, domain, _)| (*domain).to_owned())
            .collect(),
        sources: capsules
            .iter()
            .map(|(domain, capsule)| (domain.clone(), capsule))
            .collect(),
    })?)
}

fn retained_source(
    record: SourceCoverageRecord,
    committed_sequence: u64,
    verdict: Result<RetainedAbsence, RetainedCoverageRefusal>,
) -> RetainedSourceCoverage {
    RetainedSourceCoverage {
        payload_digest: record.digest(),
        record,
        committed_sequence,
        verdict,
    }
}

/// `source-domain:<domain> (record <16 hex>, commit <n>)`, the label every gap starts with.
fn source_label(domain: &str, retained: &RetainedSourceCoverage) -> String {
    let text = retained.payload_digest.to_text();
    let hex: String = text
        .split_once(':')
        .map_or(text.clone(), |(_, hex)| hex.chars().take(16).collect());
    format!(
        "source-domain:{domain} (record {hex}, commit {})",
        retained.committed_sequence
    )
}

#[test]
fn source_domains_are_covered_stale_or_not_observable_with_exact_operator_text() -> TestResult {
    let root = empty_deployment("source-domains")?;
    let anchor = read_deployment(&root, &OrientLimits::default())?.anchor;
    let interval = CaptureInterval::new(source_seconds(0)?, source_seconds(SOURCE_TICKS)?)?;
    let window = format!("[0, {}] ns", source_seconds(SOURCE_TICKS)?.0);

    // Accepted by the stored-witness rule: covered.
    let covered_record = source_record(&anchor, &[("cam-a", "domain-covered", true)])?;
    let covered = retained_source(
        covered_record.clone(),
        2,
        Ok(RetainedAbsence {
            record_digest: covered_record.digest(),
            record_sequence: 2,
            witness_digest: covered_record.witness.witness_digest(),
            witness_object: covered_record.witness_object(),
            basis_sequence: anchor.commit_sequence,
            interval,
            domains: covered_record.witness.authorized_domain.clone(),
            // Site coverage is delivery, assessed without an event: no analysis (fss-f8jls).
            analysis: None,
        }),
    );
    // Complete at its basis, invalidated by a later commit: stale.
    let stale_record = source_record(&anchor, &[("cam-b", "domain-stale", true)])?;
    assert!(stale_record.witness.certifies_absence());
    let invalidation = RetainedCoverageRefusal::CoverageRelevantCommit {
        sequence: 5,
        family: "sensor_capsule".to_owned(),
        delta_id: "delta:late".to_owned(),
    };
    assert!(invalidation.invalidated());
    let stale = retained_source(stale_record, 3, Err(invalidation.clone()));
    // One camera silent: its domain did not deliver; the delivering domain is refused too.
    let gapped_record = source_record(
        &anchor,
        &[
            ("cam-c", "domain-delivered", true),
            ("cam-d", "domain-silent", false),
        ],
    )?;
    assert!(!gapped_record.witness.certifies_absence());
    let gapped = retained_source(
        gapped_record,
        4,
        Err(RetainedCoverageRefusal::WitnessDoesNotCertify),
    );
    let refusal = RetainedCoverageRefusal::WitnessDoesNotCertify.to_string();

    let records = vec![covered.clone(), stale.clone(), gapped.clone()];
    let assessment = super::coverage::assess(
        &[],
        &records,
        &BTreeMap::new(),
        false,
        &BTreeSet::from(["zone:garage".to_owned()]),
        &BTreeSet::new(),
        &[],
    )?
    .ok_or("source records assessed to nothing")?;
    assert_eq!(assessment.record_count, 3);
    assert!(!assessment.complete());
    let zone = |scope: &str| {
        assessment
            .zones
            .iter()
            .find(|zone| zone.scope == scope)
            .ok_or_else(|| format!("no zone {scope}"))
    };

    let covered_zone = zone("source-domain:domain-covered")?;
    assert_eq!(covered_zone.state, ZoneCoverageState::Covered);
    assert_eq!(covered_zone.window, Some(interval));
    assert_eq!(
        covered_zone.witnesses,
        vec![covered.record.witness.witness_digest()]
    );
    assert!(covered_zone.gaps.is_empty());
    assert_eq!(covered_zone.provenance(), SOURCE_COVERAGE_PROVENANCE);

    let stale_zone = zone("source-domain:domain-stale")?;
    assert_eq!(stale_zone.state, ZoneCoverageState::Stale);
    assert_eq!(stale_zone.basis.as_ref(), Some(&anchor));
    assert!(stale_zone.window.is_none() && stale_zone.witnesses.is_empty());
    let stale_gap = format!(
        "{}: stale: {invalidation}; the witness no longer certifies the current anchor.",
        source_label("domain-stale", &stale)
    );
    assert_eq!(stale_zone.gaps, vec![stale_gap.clone()]);
    assert_eq!(stale_zone.provenance(), SOURCE_COVERAGE_PROVENANCE);

    let silent_zone = zone("source-domain:domain-silent")?;
    assert_eq!(silent_zone.state, ZoneCoverageState::NotObservable);
    let silent_gap = format!(
        "{}: not observable over {window}: the domain did not deliver continuously ({refusal}).",
        source_label("domain-silent", &gapped)
    );
    assert_eq!(silent_zone.gaps, vec![silent_gap.clone()]);

    let delivered_zone = zone("source-domain:domain-delivered")?;
    assert_eq!(delivered_zone.state, ZoneCoverageState::NotObservable);
    assert_eq!(
        delivered_zone.gaps,
        vec![format!(
            "{}: not observable: {refusal}.",
            source_label("domain-delivered", &gapped)
        )]
    );

    // A recorded-file or event-only scope states the recorded provenance, never the source one.
    let event_zone = zone("event-zone:zone:garage")?;
    assert_eq!(event_zone.provenance(), RECORDED_COVERAGE_PROVENANCE);
    let mut recorded = covered_zone.clone();
    recorded.scope = "zone:door".to_owned();
    assert_eq!(recorded.provenance(), RECORDED_COVERAGE_PROVENANCE);

    // The operator cells carry the exact text and state, at the head the invalidating commit
    // (5) reached.
    let mut head = anchor.clone();
    head.commit_sequence = 5;
    let covered_cell = super::zone_coverage_cell(covered_zone, &head)?;
    assert_eq!(covered_cell.knowledge_state(), KnowledgeState::Known);
    assert_eq!(
        covered_cell.statement(),
        format!(
            "source-domain:domain-covered is covered over {window} by 1 retained witness(es) of \
             pipeline generation unknown: no confirmed zone entry other than published \
             candidates. Provenance: {SOURCE_COVERAGE_PROVENANCE}."
        )
    );
    let stale_cell = super::zone_coverage_cell(stale_zone, &head)?;
    assert_eq!(stale_cell.knowledge_state(), KnowledgeState::Stale);
    assert_eq!(
        stale_cell.statement(),
        format!("source-domain:domain-stale is stale: {stale_gap}")
    );
    let silent_cell = super::zone_coverage_cell(silent_zone, &head)?;
    assert_eq!(silent_cell.knowledge_state(), KnowledgeState::NotObservable);
    assert_eq!(
        silent_cell.statement(),
        format!("source-domain:domain-silent is not_observable: {silent_gap}")
    );
    let cells = [
        covered_cell.statement().to_owned(),
        stale_cell.statement().to_owned(),
        silent_cell.statement().to_owned(),
    ];
    for text in assessment.gaps().iter().chain(cells.iter()) {
        assert!(
            !text.contains("  "),
            "run of spaces in operator text: {text:?}"
        );
    }
    fs::remove_dir_all(&root)?;
    Ok(())
}

/// These compiler fixtures add explicitly synthetic event rows to an empty verified
/// deployment. They make no claim that a sensor observed or published these hypotheses.
fn synthetic_catalogue(
    tag: &str,
    count: usize,
) -> Result<(PathBuf, super::DeploymentSnapshot), Box<dyn Error>> {
    let root = empty_deployment(tag)?;
    let mut snapshot = read_deployment(&root, &OrientLimits::default())?;
    snapshot.latest_evidence_time = TimestampNs(100);
    snapshot.event_ledger_root = Some(ContentDigest::sha256(b"synthetic-event-ledger"));
    for index in 0..count {
        snapshot.events.push(synthetic_event(index)?);
    }
    Ok((root, snapshot))
}

fn synthetic_event(index: usize) -> Result<super::RetainedEvent, Box<dyn Error>> {
    use fss_core::{DecisionPath, EventHypothesis, EventKind, EventState, ProbabilityInterval};

    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(),
        event_id: EventId::parse(format!("event:orient-scale:{index:04}"))?,
        revision: 1,
        supersedes: None,
        state: EventState::Hypothesized,
        kind: EventKind::UnknownPresence,
        interval: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
        uncertainty_reason: None,
        zone_ids: vec!["door".to_owned()],
        track_ids: Vec::new(),
        probability: ProbabilityInterval::new(0.0, 1.0)?,
        evidence: Vec::new(),
        model_receipts: Vec::new(),
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(b"orient-scale-policy"),
            fingerprint: ContentDigest::sha256(b"orient-scale-hypothesis"),
            abstained: true,
            abstention_reason: Some("synthetic hypothesis only".to_owned()),
        },
    };
    event.verify()?;
    Ok(super::RetainedEvent {
        revisions: vec![event.clone()],
        event_root: ContentDigest::sha256(format!("orient-root-{index}").as_bytes()),
        revision_digest: event.canonical_digest(EventHypothesis::SCHEMA),
        committed_sequence: 0,
        tamper: fss_core::SensorTamperStatus::default(),
        object_bytes: 100,
        object_reads: 1,
        event,
    })
}

#[test]
fn large_catalogue_preserves_all_worlds_with_bounded_projection() -> TestResult {
    let (root, mut snapshot) = synthetic_catalogue("large", super::MAX_DEPLOYMENT_EVENTS)?;
    // A large import catalogue must not reintroduce one proof pointer per import into
    // the fixed-size projection; its retained count is a ledger-derived metadata fact.
    snapshot.completed_imports = (0..super::MAX_DEPLOYMENT_EVENTS)
        .map(|index| ContentDigest::sha256(format!("synthetic-import-{index}").as_bytes()))
        .collect();
    let limits = OrientLimits::default();
    assert_eq!(limits.max_events, 4096);
    let orient_request = request(AgentView::Brief)?;
    let orientation = orient_deployment(&snapshot, &orient_request, &limits)?;
    orientation.publication.verify()?;
    orientation.capsule().validate()?;
    assert_eq!(orientation.hydration.len(), super::MAX_DEPLOYMENT_EVENTS);
    assert_eq!(
        orientation.aggregated_world_count,
        orientation
            .hydration
            .iter()
            .map(|slot| slot.world_ids.len())
            .sum::<usize>()
    );
    assert!(
        orientation
            .hydration
            .iter()
            .all(|slot| slot.physical_state != KnowledgeState::Known)
    );
    assert!(orientation.capsule().frame.evidence_handles.len() < 32);
    let receipt = &orientation.publication.compression_receipt;
    assert!(
        receipt.expansion_handles.len()
            <= fss_core::SemanticCompressionReceipt::MAX_EXPANSION_HANDLES
    );
    assert_eq!(
        receipt
            .expansion_handles
            .iter()
            .filter(|handle| handle.handle.starts_with("fss://event/"))
            .count(),
        1
    );
    let imports = orientation
        .capsule()
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id() == super::CLAIM_IMPORTS)
        .ok_or("imports cell missing")?;
    assert!(imports.statement().contains("4096 completed file imports"));
    assert_eq!(imports.evidence_digests(), vec![snapshot.anchor.state_root]);
    assert!(orientation.capsule().obligations.is_empty());
    assert!(
        orientation
            .capsule()
            .frame
            .knowledge_cells
            .iter()
            .all(|cell| !cell.is_irreversible_effect_premise(snapshot.latest_evidence_time))
    );

    // Consequence ranking, aggregate membership and publication identity do not depend
    // on the caller's in-memory event ordering.
    snapshot.events.reverse();
    let replay = orient_deployment(&snapshot, &orient_request, &limits)?;
    assert_eq!(
        orientation.publication.publication_digest,
        replay.publication.publication_digest
    );
    fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn direct_expansion_profile_is_preserved_through_128_events() -> TestResult {
    let (root, mut snapshot) = synthetic_catalogue("boundary", 128)?;
    let orient_request = request(AgentView::Brief)?;
    let legacy = super::compile_capsule(
        &snapshot,
        &orient_request,
        None,
        None,
        &[],
        super::ProjectionPurpose::Orientation,
    )?;
    assert_eq!(legacy.source.handles.len(), 128);
    assert!(
        legacy
            .source
            .handles
            .iter()
            .all(|handle| handle.handle.starts_with("fss://event/"))
    );
    for event in &snapshot.events {
        assert!(legacy.proof_roots.contains(&event.event_root));
        assert!(legacy.proof_roots.contains(&event.revision_digest));
    }
    let detail = legacy
        .source
        .omissions
        .iter()
        .find(|omission| omission.class == super::SOURCE_CLASS_EVENT_DETAIL)
        .and_then(|omission| omission.transform.details.as_deref())
        .ok_or("legacy event omission missing")?;
    assert_eq!(
        detail,
        "128 of 128 events are summarized by claim:deployment:events and the \
         per-state epistemic boundaries; each event's cells hydrate through its handle."
    );

    snapshot.events.push(synthetic_event(128)?);
    let grouped = super::compile_capsule(
        &snapshot,
        &orient_request,
        None,
        None,
        &[],
        super::ProjectionPurpose::Orientation,
    )?;
    assert_eq!(grouped.hydration.len(), 129);
    assert_eq!(grouped.source.handles.len(), 2);
    assert!(grouped.proof_roots.len() < legacy.proof_roots.len());
    assert_eq!(
        grouped.aggregated_world_count,
        legacy.aggregated_world_count + grouped.hydration[128].world_ids.len()
    );
    fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn grouped_inventory_enumerates_every_exact_event_root_and_reaches_explanation() -> TestResult {
    use crate::agent_follow::{AnchorToken, snapshot_anchor_token};
    use crate::agent_query::{EventQueryFilter, EventQueryRequest, query_deployment};

    let (root, snapshot) = synthetic_catalogue("inventory", 257)?;
    let mut orient_request = request(AgentView::Brief)?;
    // The portable stable-ID bound admits 128 characters and refuses 129.
    orient_request.principal = PrincipalId::parse("p".repeat(128))?;
    assert!(PrincipalId::parse("p".repeat(129)).is_err());
    let orientation = orient_deployment(&snapshot, &orient_request, &OrientLimits::default())?;
    let anchor = snapshot_anchor_token(&snapshot);
    let inventory = orientation
        .publication
        .compression_receipt
        .expansion_handles
        .iter()
        .find(|handle| handle.handle.ends_with(&format!("/anchor/{anchor}")))
        .ok_or("exact-anchor inventory missing")?;
    assert!(inventory.handle.len() <= 256);
    assert!(inventory.purpose.len() <= 1024);
    assert!(inventory.purpose.contains("--max-entries 32"));
    assert!(
        inventory
            .purpose
            .contains("estimated cost is per metadata page")
    );
    assert!(
        inventory
            .purpose
            .contains(orient_request.principal.as_str())
    );
    assert!(
        inventory
            .purpose
            .contains("metadata, not H1/source hydration")
    );
    let mut query_request = EventQueryRequest {
        filter: EventQueryFilter::default(),
        principal: orient_request.principal.clone(),
        max_entries: 32,
        expected_anchor: Some(AnchorToken::parse(&anchor).ok_or("invalid emitted anchor")?),
        continuation: None,
    };
    let mut roots = BTreeMap::new();
    loop {
        let page = query_deployment(&snapshot, &query_request)?;
        assert_eq!(page.anchor_token, anchor);
        for row in &page.events {
            assert!(
                roots
                    .insert(
                        row.event.event_id.clone(),
                        (row.event_root, row.revision_digest)
                    )
                    .is_none()
            );
        }
        match &page.page.next_cursor {
            Some(next) => query_request.continuation = Some(next.token().to_owned()),
            None => break,
        }
    }
    assert_eq!(roots.len(), snapshot.events.len());
    for row in &snapshot.events {
        assert_eq!(
            roots.get(&row.event.event_id),
            Some(&(row.event_root, row.revision_digest))
        );
    }
    let last = snapshot.events.last().ok_or("last event missing")?;
    let explanation = explain_event(&snapshot, &orientation, &last.event.event_id)?
        .ok_or("inventory event cannot be explained")?;
    assert_eq!(explanation.hydration.event_id, last.event.event_id);
    assert_eq!(explanation.hydration.revision_digest, last.revision_digest);

    let mut changed = snapshot.clone();
    changed.effect_journal_root = ContentDigest::sha256(b"later-effect-record");
    assert!(matches!(
        query_deployment(&changed, &query_request),
        Err(crate::agent_query::QueryError::AnchorChanged)
    ));
    fs::remove_dir_all(&root)?;
    Ok(())
}

fn add_synthetic_edge(
    row: &mut super::RetainedEvent,
    relation: fss_core::EvidenceEdgeRelation,
) -> Result<ContentDigest, Box<dyn Error>> {
    let digest = ContentDigest::sha256(
        format!("synthetic-{}-{}", relation.as_str(), row.event.event_id).as_bytes(),
    );
    row.event.evidence.push(fss_core::EventEvidence {
        digest,
        class: fss_core::EvidenceClass::Derived,
        failure_domain: "sensor:scale-risk".to_owned(),
        supports: false,
        relation,
        capsule_digest: None,
        identity_digest: None,
    });
    row.event.verify()?;
    row.revisions = vec![row.event.clone()];
    row.revision_digest = row
        .event
        .canonical_digest(fss_core::EventHypothesis::SCHEMA);
    row.tamper = fss_core::event::compute_sensor_tamper_status(row.revisions.iter(), None);
    Ok(digest)
}

#[test]
fn late_conflicts_and_tamper_remain_inline_and_never_disappear_into_inventory() -> TestResult {
    use fss_core::EvidenceEdgeRelation;

    let (root, mut snapshot) = synthetic_catalogue("protected", 258)?;
    let contradiction =
        add_synthetic_edge(&mut snapshot.events[256], EvidenceEdgeRelation::Contradicts)?;
    let tamper = add_synthetic_edge(
        &mut snapshot.events[257],
        EvidenceEdgeRelation::SensorTamper,
    )?;
    let compiled = super::compile_capsule(
        &snapshot,
        &request(AgentView::Brief)?,
        None,
        None,
        &[],
        super::ProjectionPurpose::Orientation,
    )?;
    for row in &snapshot.events[256..] {
        let slot = compiled
            .hydration
            .iter()
            .find(|slot| slot.event_id == row.event.event_id)
            .ok_or("protected hydration slot missing")?;
        assert!(slot.cells_inline);
        assert!(
            compiled
                .source
                .handles
                .iter()
                .any(|handle| handle.handle == slot.handle)
        );
        assert!(compiled.proof_roots.contains(&row.event_root));
        assert!(compiled.proof_roots.contains(&row.revision_digest));
    }
    assert!(compiled.proof_roots.contains(&contradiction));
    assert!(compiled.proof_roots.contains(&tamper));
    assert!(
        compiled
            .capsule
            .frame
            .knowledge_cells
            .iter()
            .any(|cell| cell.contradictions().contains(&contradiction))
    );
    assert!(
        compiled
            .capsule
            .frame
            .world_envelope
            .adversarial_residuals
            .iter()
            .any(|world| world.world_id.ends_with("sensor-tamper")
                && world.protected
                && world.consequence_severity == 5)
    );

    for row in &mut snapshot.events {
        if !row.tamper.has_open_tamper() {
            add_synthetic_edge(row, EvidenceEdgeRelation::SensorTamper)?;
        }
    }
    let planned = super::planned_events(&snapshot, AgentView::Brief)?;
    assert!(planned.iter().all(|event| event.inline));
    // The fixed token budget and 256-handle receipt bound still refuse overload.
    assert!(
        orient_deployment(
            &snapshot,
            &request(AgentView::Brief)?,
            &OrientLimits::default()
        )
        .is_err()
    );
    fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn deployment_event_bound_cannot_be_bypassed_by_custom_limits() -> TestResult {
    let (root, snapshot) = synthetic_catalogue("over-bound", super::MAX_DEPLOYMENT_EVENTS + 1)?;
    let limits = OrientLimits {
        max_events: usize::MAX,
        ..OrientLimits::default()
    };
    assert!(matches!(
        orient_deployment(&snapshot, &request(AgentView::Brief)?, &limits),
        Err(OrientError::TooManyEvents {
            published: 4097,
            maximum: 4096
        })
    ));
    fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn reader_refuses_event_count_before_attempting_event_object_hydration() -> TestResult {
    let root = empty_deployment("reader-bound")?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:orient-reader-bound".to_owned(),
        operation_id: OperationId::parse("operation:orient-reader-bound")?,
        principal: "operator:orient-reader-bound".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: ContentDigest::sha256(b"orient-reader-bound"),
        generation: 1,
    })?;
    let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority,
        root.join("reader-bound-cx"),
    )?);
    let mut deployment = ReferenceDeployment::open(&root, "site:orient-unit", &cx)?;
    deployment.publish_event(
        &crate::ReferencePolicyDecision {
            event: synthetic_event(0)?.event,
            action: crate::ReferencePolicyAction::Hold,
        },
        &cx,
    )?;
    drop(deployment);
    let limits = OrientLimits {
        max_events: 0,
        max_object_bytes: 0,
        ..OrientLimits::default()
    };
    assert!(matches!(
        read_deployment(&root, &limits),
        Err(DeploymentReadError::Unreadable { reason })
            if reason == "complete event catalogue has 1 events, above the read bound 0"
    ));
    fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn orient_succeeds_after_retaining_many_coverage_witnesses_across_five_sensors() -> TestResult {
    use crate::agent_orient::RetainedCoverage;
    use crate::ingest::recorded_coverage::{
        CoverageRecord, CoverageSource, UncoveredInterval, UncoveredReason, ZoneCoverage,
        ZoneWitness,
    };
    use fss_core::{Completeness, CoverageContinuity, CoverageStopReason, CoverageWitness};

    let root = empty_deployment("many-coverage-witnesses")?;
    let mut snapshot = read_deployment(&root, &OrientLimits::default())?;
    let anchor = snapshot.anchor.clone();
    let pipeline_generation = ContentDigest::sha256(b"pipeline:five-cam-regression");

    // Reproduces the 5-camera intrusion coverage shape (36 + 12 + 11 + 19 + 27 = 105 witnesses
    // with >100 uncovered intervals and >20 KiB of gap text per camera).
    let counts = [
        ("sensor:gate", 36_u64),
        ("sensor:driveway", 12_u64),
        ("sensor:doorbell", 11_u64),
        ("sensor:porch", 19_u64),
        ("sensor:entry", 27_u64),
    ];
    for (seq_offset, (sensor, witness_count)) in counts.into_iter().enumerate() {
        let committed_sequence = 11_u64 + seq_offset as u64;
        let mut witnesses = Vec::new();
        let mut uncovered = Vec::new();
        for idx in 0..witness_count {
            let start_ns = i128::from(idx * 2_000_000_000);
            let mid_ns = start_ns + 1_000_000_000;
            let gap_end_ns = start_ns + 1_800_000_000;
            let covered = CaptureInterval::new(TimestampNs(start_ns), TimestampNs(mid_ns))?;
            let witness = CoverageWitness {
                anchor: anchor.clone(),
                negative_predicate: "no_unknown_person_entry".to_owned(),
                authorized_domain: BTreeSet::from([format!("{sensor}:zone:yard")]),
                observed_domain: BTreeSet::from([format!("{sensor}:zone:yard")]),
                excluded_domain: BTreeSet::new(),
                authorized_generation: 1,
                observed_generation: 1,
                continuity: CoverageContinuity::Continuous,
                completeness: Completeness::Complete,
                stop_reason: CoverageStopReason::Complete,
            };
            witnesses.push(ZoneWitness {
                first_segment: idx * 10,
                last_segment: idx * 10 + 5,
                frames: 6,
                outer: covered,
                covered,
                witness,
            });
            uncovered.push(UncoveredInterval {
                first_segment: idx * 10 + 6,
                last_segment: idx * 10 + 9,
                capture: Some(CaptureInterval::new(
                    TimestampNs(mid_ns),
                    TimestampNs(gap_end_ns),
                )?),
                reason: UncoveredReason::ConfirmationLatency,
            });
        }
        let analysed = CaptureInterval::new(
            TimestampNs(0),
            TimestampNs(i128::from(witness_count * 2_000_000_000)),
        )?;
        let record = CoverageRecord {
            source: CoverageSource::Watch,
            import_identity: ContentDigest::sha256(format!("import:{sensor}").as_bytes()),
            import_root: ContentDigest::sha256(format!("root:{sensor}").as_bytes()),
            sensor_id: sensor.to_owned(),
            analysis_digest: ContentDigest::sha256(format!("analysis:{sensor}").as_bytes()),
            basis: anchor.clone(),
            capture_time_label: "operator_assumption".to_owned(),
            first_segment: 0,
            last_segment: witness_count * 10,
            analysed,
            zones: vec![ZoneCoverage {
                scope: "zone:yard".to_owned(),
                zone_id: "yard".to_owned(),
                geometry: "0,0,640,480".to_owned(),
                pipeline_generation,
                witnesses,
                uncovered,
                visibility: None,
                pose_robustness: None,
            }],
            pose_provenance: None,
            pose_uncertainty: None,
            sensor_health: None,
        };
        snapshot.coverage.push(RetainedCoverage {
            payload_digest: ContentDigest::sha256(format!("cov-rec:{sensor}").as_bytes()),
            record,
            committed_sequence,
            privacy_policy_digest: None,
            privacy_generation: None,
            calibration_invalidation: None,
        });
    }

    for view in [AgentView::Brief, AgentView::EpistemicMap] {
        let orientation = orient_deployment(&snapshot, &request(view)?, &OrientLimits::default())?;
        assert_eq!(orientation.epistemic_state, KnowledgeState::NotObservable);
        let coverage = orientation.coverage.as_ref().ok_or("missing coverage")?;
        assert_eq!(coverage.zones.len(), 5);
        assert!(coverage.gaps().len() >= 105);
        // Every critical coverage cell stays well below SemanticContextPack's 16 KiB limit
        // while preserving explicit overflow counts and hydration hints.
        let gate_cell = orientation
            .capsule()
            .frame
            .knowledge_cells
            .iter()
            .find(|c| c.statement().contains("sensor:gate zone:yard"))
            .ok_or("missing gate zone coverage cell")?;
        assert_eq!(gate_cell.knowledge_state(), KnowledgeState::NotObservable);
        assert!(gate_cell.statement().len() < 2048);
        assert!(gate_cell.statement().contains("further coverage gap(s)"));
        assert!(
            gate_cell
                .statement()
                .contains("situationFrame.coverage.gaps")
        );
    }
    fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn why_not_explanation_and_h2_graph_neighborhood_work_end_to_end() -> TestResult {
    let root = empty_deployment("why-not-and-h2")?;
    let limits = OrientLimits::default();
    let mut snapshot = read_deployment(&root, &limits)?;
    let event_id = EventId::parse("event:why-not-single-domain")?;
    let evidence_digest = ContentDigest::sha256(b"single-domain-evidence");
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(),
        event_id: event_id.clone(),
        revision: 1,
        supersedes: None,
        state: EventState::Witnessed,
        kind: EventKind::UnknownPresence,
        interval: CaptureInterval::new(TimestampNs(1_000), TimestampNs(2_000))?,
        uncertainty_reason: Some("single_sensor_only".to_owned()),
        zone_ids: vec!["zone:porch".to_owned()],
        track_ids: Vec::new(),
        probability: ProbabilityInterval::new(0.0, 1.0)?,
        evidence: vec![EventEvidence {
            digest: evidence_digest,
            class: EvidenceClass::Derived,
            failure_domain: "domain:porch-cam".to_owned(),
            supports: true,
            relation: EvidenceEdgeRelation::Supports,
            capsule_digest: Some(ContentDigest::sha256(b"cap:porch:1")),
            identity_digest: None,
        }],
        model_receipts: vec![evidence_digest],
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(b"policy:test:v1"),
            fingerprint: ContentDigest::sha256(b"fp:test:1"),
            abstained: false,
            abstention_reason: None,
        },
    };
    event.validate()?;
    let revision_digest = event.revision_digest();
    let event_root = ContentDigest::sha256(b"root:event:why-not-single-domain");
    snapshot.latest_evidence_time = TimestampNs(2_000);
    snapshot.events.push(RetainedEvent {
        event: event.clone(),
        revisions: vec![event],
        event_root,
        revision_digest,
        committed_sequence: 1,
        tamper: SensorTamperStatus::default(),
        object_bytes: 256,
        object_reads: 2,
    });

    let orientation = orient_deployment(&snapshot, &request(AgentView::Brief)?, &limits)?;
    let why_not =
        explain_event_with_question(&snapshot, &orientation, &event_id, ExplainQuestion::WhyNot)?
            .ok_or("expected why_not explanation")?;
    assert_eq!(why_not.receipt.question(), ExplainQuestion::WhyNot);
    assert!(
        why_not
            .would_change
            .iter()
            .any(|line| line.contains("Why not corroborated"))
    );
    assert!(
        why_not
            .would_change
            .iter()
            .any(|line| line.contains("Why not certified absent"))
    );
    assert!(
        why_not
            .would_change
            .iter()
            .any(|line| line.contains("Why not narrowed to a calibrated probability"))
    );

    let h2 = crate::agent_event_hydration::build_event_h2_graph_neighborhood(
        &snapshot,
        &orientation,
        &event_id,
        revision_digest,
        "grant:agent-h2-neighborhood:1",
        TimestampNs(10_000),
    )?;
    assert_eq!(h2.subject_digest(), revision_digest);
    assert_eq!(h2.privacy_class(), "private:property");
    assert_eq!(
        h2.applied_redaction_transform(),
        "transform:graph_neighborhood_redact"
    );
    assert!(matches!(
        h2.artifact_kind(),
        fss_core::DecisionArtifactKind::GraphNeighborhood(_)
    ));

    fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn cancellable_history_preserves_retained_and_historical_snapshot_semantics() -> TestResult {
    let root = empty_deployment("cancellable-history")?;
    let limits = OrientLimits::default();
    let initial = super::DeploymentHistory::read(&root, &limits)?.head();
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:cancellable-history".to_owned(),
        operation_id: OperationId::parse("operation:cancellable-history")?,
        principal: "operator:cancellable-history".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: ContentDigest::sha256(b"cancellable-history"),
        generation: 1,
    })?;
    let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority,
        root.join("cancellable-history-cx"),
    )?);
    let mut deployment = ReferenceDeployment::open(&root, "site:orient-unit", &cx)?;
    deployment.publish_event(
        &crate::ReferencePolicyDecision {
            event: synthetic_event(0)?.event,
            action: crate::ReferencePolicyAction::Hold,
        },
        &cx,
    )?;
    drop(deployment);
    let ordinary = super::DeploymentHistory::read(&root, &limits)?;
    let admitted = super::DeploymentHistory::read_cancellable(&root, &limits, &|| false)?;
    assert_eq!(ordinary.head(), admitted.head());
    for position in [initial, ordinary.head()] {
        assert_eq!(
            ordinary.snapshot_at(position)?,
            admitted.snapshot_at_cancellable(position, &|| false)?,
        );
    }
    let snapshot = read_deployment(&root, &limits)?;
    let cancellable = super::read_deployment_cancellable(&root, &limits, &|| false)?;
    assert_eq!(snapshot, cancellable);
    assert_eq!(
        orient_deployment(&snapshot, &request(AgentView::Brief)?, &limits)?
            .capsule()
            .decision_fingerprint()?,
        orient_deployment(&cancellable, &request(AgentView::Brief)?, &limits)?
            .capsule()
            .decision_fingerprint()?,
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn cancelled_legacy_reads_cannot_report_missing_roots_or_empty_successes() -> TestResult {
    let missing = fresh_root("cancelled-missing-read")?;
    let limits = OrientLimits::default();
    let failure = super::read_deployment_cancellable(&missing, &limits, &|| true);
    assert!(matches!(
        failure,
        Err(DeploymentReadError::Corrupt { reason })
            if reason == "retained read authority cancelled"
    ));
    assert!(!missing.exists());
    assert_eq!(
        read_deployment(&missing, &limits),
        super::read_deployment_cancellable(&missing, &limits, &|| false),
    );
    let root = empty_deployment("cancelled-empty-snapshot")?;
    let history = super::DeploymentHistory::read(&root, &limits)?;
    assert!(
        history
            .snapshot_at_cancellable(history.head(), &|| true)
            .is_err()
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn reader_discards_a_payload_when_cancellation_arrives_at_any_read_checkpoint() -> TestResult {
    use std::cell::Cell;

    let root = fresh_root("read-checkpoints")?;
    fs::create_dir_all(&root)?;
    let path = root.join("payload");
    fs::write(&path, b"retained payload")?;
    let calls = Cell::new(0_usize);
    let count = || {
        calls.set(calls.get() + 1);
        false
    };
    let mut baseline = Reader {
        files_read: 0,
        bytes_read: 0,
        budget: None,
        cancelled: Some(&count),
        pack_catalog: None,
    };
    assert_eq!(
        baseline.read_file(&path, 64)?,
        Some(b"retained payload".to_vec())
    );
    for cut in 1..=calls.get() {
        let observed = Cell::new(0_usize);
        let cancel = || {
            observed.set(observed.get() + 1);
            observed.get() >= cut
        };
        let budget = MetadataReadBudget::new(64, 1);
        let mut reader = Reader {
            files_read: 0,
            bytes_read: 0,
            budget: Some(budget.clone()),
            cancelled: Some(&cancel),
            pack_catalog: None,
        };
        assert!(reader.read_file(&path, 64).is_err(), "cut {cut}");
        assert!(budget.ensure_valid().is_err(), "cut {cut}");
        assert_eq!(reader.files_read, 0, "cut {cut}");
    }
    assert_eq!(fs::read(&path)?, b"retained payload");
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn ordinary_ledger_adapter_discards_bytes_when_cancelled_during_read() -> TestResult {
    use fss_ledger::JournalReadIo;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let root = fresh_root("journal-read-checkpoints")?;
    fs::create_dir_all(&root)?;
    let path = root.join("journal");
    fs::write(&path, b"ledger bytes")?;
    let calls = AtomicUsize::new(0);
    let cancel_after_read = || calls.fetch_add(1, Ordering::SeqCst) >= 1;
    let journal = super::CancellableHistoryJournal {
        cancelled: &cancel_after_read,
    };
    assert!(journal.read_bounded(&path, 64).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(fs::read(&path)?, b"ledger bytes");
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn pulse_stays_within_300_token_cap_across_2_10_and_50_cameras_without_omitting_critical_items()
-> TestResult {
    let limits = OrientLimits::default();
    for camera_count in [2_usize, 10, 50] {
        let tag = format!("pulse-scale-{camera_count}");
        let (root, mut snapshot) = synthetic_catalogue(&tag, camera_count.min(8))?;
        snapshot.completed_imports = (0..camera_count * 4)
            .map(|idx| ContentDigest::sha256(format!("import:{camera_count}:{idx}").as_bytes()))
            .collect();
        snapshot.import_ledger_root = Some(ContentDigest::sha256(b"import-ledger-root"));
        let anchor = snapshot.anchor.clone();
        let interval = CaptureInterval::new(source_seconds(0)?, source_seconds(SOURCE_TICKS)?)?;
        for cam in 0..camera_count {
            let sensor = format!("cam-{cam:03}");
            let domain = format!("domain-{cam:03}");
            let delivered = cam % 3 != 0;
            let record = source_record(&anchor, &[(&sensor, &domain, delivered)])?;
            let verdict = if delivered {
                Ok(RetainedAbsence {
                    record_digest: record.digest(),
                    record_sequence: (cam as u64) + 1,
                    witness_digest: record.witness.witness_digest(),
                    witness_object: record.witness_object(),
                    basis_sequence: anchor.commit_sequence,
                    interval,
                    domains: record.witness.authorized_domain.clone(),
                    analysis: None,
                })
            } else {
                Err(RetainedCoverageRefusal::WitnessDoesNotCertify)
            };
            snapshot
                .source_coverage
                .push(retained_source(record, (cam as u64) + 1, verdict));
        }

        let orientation = orient_deployment(&snapshot, &request(AgentView::Pulse)?, &limits)?;
        orientation.publication.verify()?;
        orientation.capsule().validate()?;
        assert!(
            orientation.consumed.tokens <= u64::from(AgentView::Pulse.maximum_tokens()),
            "cameras={camera_count}: pulse consumed {} tokens > {}",
            orientation.consumed.tokens,
            AgentView::Pulse.maximum_tokens()
        );
        let receipt = &orientation.publication.compression_receipt;
        assert_eq!(
            receipt.critical_preservation.omitted_critical_items, 0,
            "cameras={camera_count}: pulse omitted critical items"
        );
        let zone_cell = orientation
            .capsule()
            .frame
            .knowledge_cells
            .iter()
            .find(|cell| cell.claim_id() == CLAIM_COVERAGE)
            .ok_or("expected rolled-up claim:coverage:site in multi-camera pulse")?;
        assert_eq!(
            zone_cell.knowledge_state(),
            KnowledgeState::NotObservable,
            "worst-case epistemic state must be preserved across rolled-up zones"
        );
        let expected_zones = camera_count + 1; // camera_count source domains + "door" event zone
        assert!(
            zone_cell
                .statement()
                .contains(&format!("{expected_zones} zones:")),
            "expected multi-zone rollup counts in pulse coverage cell: {}",
            zone_cell.statement()
        );
        assert!(
            receipt.omitted_classes.contains("zone_coverage_detail"),
            "expected zone_coverage_detail compression omission in pulse receipt"
        );
        for affordance in &orientation.capsule().affordances {
            assert!(
                !affordance.rationale.contains("  "),
                "duplicate-space typo in {}: {:?}",
                affordance.affordance_id,
                affordance.rationale
            );
        }
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn dynamic_orient_plan_affordance_tracks_corroboration_contradiction_and_tamper() -> TestResult {
    let root = empty_deployment("dynamic-plan-affordance")?;
    let limits = OrientLimits::default();
    let base_snapshot = read_deployment(&root, &limits)?;

    let make_evidence = |tag: &[u8], domain: &str, relation: EvidenceEdgeRelation| EventEvidence {
        digest: ContentDigest::sha256(tag),
        class: EvidenceClass::Derived,
        failure_domain: domain.to_owned(),
        supports: matches!(relation, EvidenceEdgeRelation::Supports),
        relation,
        capsule_digest: None,
        identity_digest: None,
    };

    let make_retained = |id: &str,
                         state: EventState,
                         evidence: Vec<EventEvidence>,
                         tamper: SensorTamperStatus|
     -> Result<RetainedEvent, Box<dyn Error>> {
        let event = EventHypothesis {
            schema: EventHypothesis::SCHEMA.to_owned(),
            event_id: EventId::parse(id)?,
            revision: 1,
            supersedes: None,
            state,
            kind: EventKind::PerimeterBreach,
            interval: CaptureInterval::new(TimestampNs(1_000), TimestampNs(2_000))?,
            uncertainty_reason: if state == EventState::Indeterminate {
                Some("single sensor only".to_owned())
            } else {
                None
            },
            zone_ids: vec!["zone:front-door".to_owned()],
            track_ids: vec!["track:1".to_owned()],
            probability: ProbabilityInterval::new(0.8, 0.95)?,
            evidence,
            model_receipts: Vec::new(),
            decision_path: DecisionPath {
                policy_generation: ContentDigest::sha256(b"policy:dynamic-plan"),
                fingerprint: ContentDigest::sha256(id.as_bytes()),
                abstained: state != EventState::Corroborated,
                abstention_reason: if state == EventState::Corroborated {
                    None
                } else {
                    Some("requires corroboration".to_owned())
                },
            },
        };
        let rev = event.revision_digest();
        Ok(RetainedEvent {
            event_root: ContentDigest::sha256(format!("root:{id}").as_bytes()),
            revision_digest: rev,
            committed_sequence: 1,
            tamper,
            object_bytes: 256,
            object_reads: 2,
            revisions: vec![event.clone()],
            event,
        })
    };

    // 1. Single-camera / uncorroborated event -> Blocked (never exposed as executable in next).
    let mut single_snap = base_snapshot.clone();
    single_snap.events = vec![make_retained(
        "event:single-cam-1",
        EventState::Indeterminate,
        vec![make_evidence(
            b"cam-a",
            "sensor:cam-a",
            EvidenceEdgeRelation::Supports,
        )],
        SensorTamperStatus::default(),
    )?];
    let single_orient = orient_deployment(&single_snap, &request(AgentView::Brief)?, &limits)?;
    single_orient.capsule().validate()?;
    let single_plan = single_orient
        .capsule()
        .affordances
        .iter()
        .find(|a| a.affordance_id == AFFORDANCE_PLAN)
        .ok_or("missing plan affordance for single-camera")?;
    assert_eq!(single_plan.class, AffordanceClass::Blocked);
    assert!(
        !single_orient
            .capsule()
            .frame
            .next
            .contains(&AFFORDANCE_PLAN.to_owned())
    );
    assert!(single_plan.rationale.contains("corroboration"));
    assert!(!single_plan.rationale.contains("  "));

    // 2. Clean 2-camera independent corroborated event -> Robust & actionable in frame.next.
    let mut corr_snap = base_snapshot.clone();
    corr_snap.events = vec![make_retained(
        "event:corr-clean-1",
        EventState::Corroborated,
        vec![
            make_evidence(b"cam-a-1", "domain:cam-a", EvidenceEdgeRelation::Supports),
            make_evidence(b"cam-b-1", "domain:cam-b", EvidenceEdgeRelation::Supports),
        ],
        SensorTamperStatus::default(),
    )?];
    let corr_orient = orient_deployment(&corr_snap, &request(AgentView::Brief)?, &limits)?;
    corr_orient.capsule().validate()?;
    let corr_plan = corr_orient
        .capsule()
        .affordances
        .iter()
        .find(|a| a.affordance_id == AFFORDANCE_PLAN)
        .ok_or("missing plan affordance for corroborated")?;
    assert_eq!(corr_plan.class, AffordanceClass::Robust);
    assert_eq!(corr_plan.target, "fss://event/event:corr-clean-1");
    assert!(
        corr_orient
            .capsule()
            .frame
            .next
            .contains(&AFFORDANCE_PLAN.to_owned())
    );
    assert!(corr_plan.rationale.contains("event:corr-clean-1"));
    assert!(
        corr_plan
            .rationale
            .contains("never grants effect authority")
    );
    assert!(!corr_plan.rationale.contains("  "));

    // 3. Corroborated event with open contradiction -> Conditional with branch predicate & unsafe worlds.
    let mut cond_snap = base_snapshot.clone();
    cond_snap.events = vec![make_retained(
        "event:corr-cond-1",
        EventState::Corroborated,
        vec![
            make_evidence(b"cam-a-2", "domain:cam-a", EvidenceEdgeRelation::Supports),
            make_evidence(b"cam-b-2", "domain:cam-b", EvidenceEdgeRelation::Supports),
            make_evidence(
                b"cam-c-contra",
                "domain:cam-c",
                EvidenceEdgeRelation::Contradicts,
            ),
        ],
        SensorTamperStatus::default(),
    )?];
    let cond_orient = orient_deployment(&cond_snap, &request(AgentView::Brief)?, &limits)?;
    cond_orient.capsule().validate()?;
    let cond_plan = cond_orient
        .capsule()
        .affordances
        .iter()
        .find(|a| a.affordance_id == AFFORDANCE_PLAN)
        .ok_or("missing plan affordance for conditional")?;
    assert_eq!(cond_plan.class, AffordanceClass::Conditional);
    assert!(cond_plan.branch_predicate.is_some());
    assert!(!cond_plan.unsafe_worlds.is_empty());
    assert!(
        cond_orient
            .capsule()
            .frame
            .next
            .contains(&AFFORDANCE_PLAN.to_owned())
    );
    assert!(!cond_plan.rationale.contains("  "));

    // 4. Corroborated event with open sensor tamper -> Blocked.
    let mut tamper_snap = base_snapshot;
    let open_tamper = SensorTamperStatus {
        open_tamper_roots: vec![ContentDigest::sha256(b"tamper-root")],
        ..SensorTamperStatus::default()
    };
    tamper_snap.events = vec![make_retained(
        "event:corr-tamper-1",
        EventState::Corroborated,
        vec![
            make_evidence(b"cam-a-3", "domain:cam-a", EvidenceEdgeRelation::Supports),
            make_evidence(b"cam-b-3", "domain:cam-b", EvidenceEdgeRelation::Supports),
        ],
        open_tamper,
    )?];
    let tamper_orient = orient_deployment(&tamper_snap, &request(AgentView::Brief)?, &limits)?;
    tamper_orient.capsule().validate()?;
    let tamper_plan = tamper_orient
        .capsule()
        .affordances
        .iter()
        .find(|a| a.affordance_id == AFFORDANCE_PLAN)
        .ok_or("missing plan affordance for tamper")?;
    assert_eq!(tamper_plan.class, AffordanceClass::Blocked);
    assert!(
        !tamper_orient
            .capsule()
            .frame
            .next
            .contains(&AFFORDANCE_PLAN.to_owned())
    );
    assert!(tamper_plan.rationale.contains("tamper"));
    assert!(!tamper_plan.rationale.contains("  "));

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn privacy_mask_unbounded_horizon_does_not_poison_latest_evidence_time() -> TestResult {
    let root = empty_deployment("mask-horizon")?;
    let spec = RootAuthoritySpec {
        trace_id: "trace:mask-horizon".to_string(),
        operation_id: OperationId::parse("operation:mask-horizon")?,
        principal: "operator:mask-horizon".to_string(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"mask-horizon"),
        generation: 1,
    };
    let authority = ContextAuthority::new_root(spec)?;
    let scratch =
        std::env::temp_dir().join(format!("fss-agent-orient-mask-cx-{}", std::process::id()));
    let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority, scratch,
    )?);
    let mut dep = ReferenceDeployment::open(&root, "site:orient-unit", &cx)?;
    let real_t = TimestampNs(1_700_000_000_000_000_000);

    // 1. Commit a policy delta carrying the unbounded-horizon sentinel [0, i64::MAX] (as emitted by
    //    privacy mask declarations).
    let mask_digest = dep
        .publisher_mut()
        .stage_object(b"privacy-mask-policy-sentinel")?;
    let _ = dep.append_batch(
        fss_core::BatchId::parse("batch:mask-horizon:1")?,
        vec![fss_core::EvidenceDelta {
            delta_id: "delta:mask-horizon:1".to_owned(),
            object_id: fss_core::ObjectId::parse("object:policy-horizon:cam1")?,
            family: "operator_policy".to_owned(),
            prior_generation: None,
            new_generation: 1,
            payload_digest: mask_digest,
            witness_digest: None,
            validity: CaptureInterval::new(TimestampNs(0), TimestampNs(i128::from(i64::MAX)))?,
            plane: fss_core::Plane::Authority,
            operation_id: None,
        }],
        vec![mask_digest],
        &cx,
    )?;

    // 2. Commit a normal evidence delta at real_t.
    let ev_digest = dep.publisher_mut().stage_object(b"real-evidence-at-t0")?;
    let _ = dep.append_batch(
        fss_core::BatchId::parse("batch:mask-horizon:2")?,
        vec![fss_core::EvidenceDelta {
            delta_id: "delta:mask-horizon:2".to_owned(),
            object_id: fss_core::ObjectId::parse("object:note:cam1")?,
            family: "operator_note".to_owned(),
            prior_generation: None,
            new_generation: 1,
            payload_digest: ev_digest,
            witness_digest: None,
            validity: CaptureInterval::new(real_t, real_t)?,
            plane: fss_core::Plane::Authority,
            operation_id: None,
        }],
        vec![ev_digest],
        &cx,
    )?;
    drop(dep);

    let snap = read_deployment(&root, &OrientLimits::default())?;
    assert_eq!(
        snap.latest_evidence_time, real_t,
        "unbounded privacy-mask validity [0, i64::MAX] must NOT poison latest_evidence_time"
    );
    let orient = orient_deployment(&snap, &request(AgentView::Brief)?, &OrientLimits::default())?;
    assert_eq!(orient.capsule().created_at, real_t);

    fs::remove_dir_all(root)?;
    Ok(())
}
