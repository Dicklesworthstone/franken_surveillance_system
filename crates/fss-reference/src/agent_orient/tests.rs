#![forbid(unsafe_code)]
//! Unit tests for the read-only orientation compiler over real on-disk deployments.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::{
    AffordanceClass, AgentView, BudgetVector, CapsuleId, CaptureInterval, ClockBasis,
    ContentDigest, ContextAuthority, EventId, KnowledgeState, LedgerAnchor, OperationId,
    PrincipalId, RootAuthoritySpec, SensorCapsule, SensorId, SensorSourceBytesSpec, StreamId,
    TimestampNs,
};

use super::{
    AFFORDANCE_PLAN, AFFORDANCE_REORIENT, CLAIM_COVERAGE, CLAIM_LEDGER_HEAD, DeploymentReadError,
    OrientError, OrientLimits, OrientRequest, RECORDED_COVERAGE_PROVENANCE, RetainedSourceCoverage,
    SOURCE_COVERAGE_PROVENANCE, WORLD_UNOBSERVED_ACTIVITY, ZoneCoverageState, explain_event,
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
    )
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
    let legacy = super::compile_capsule(&snapshot, &orient_request, &[], &[], &[], &[])?;
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
    let grouped = super::compile_capsule(&snapshot, &orient_request, &[], &[], &[], &[])?;
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
    assert!(inventory.purpose.contains("estimated cost is per metadata page"));
    assert!(inventory.purpose.contains(orient_request.principal.as_str()));
    assert!(inventory.purpose.contains("metadata, not H1/source hydration"));
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
    row.revision_digest = row.event.canonical_digest(fss_core::EventHypothesis::SCHEMA);
    row.tamper = fss_core::event::compute_sensor_tamper_status(row.revisions.iter(), None);
    Ok(digest)
}

#[test]
fn late_conflicts_and_tamper_remain_inline_and_never_disappear_into_inventory() -> TestResult {
    use fss_core::EvidenceEdgeRelation;

    let (root, mut snapshot) = synthetic_catalogue("protected", 258)?;
    let contradiction = add_synthetic_edge(
        &mut snapshot.events[256],
        EvidenceEdgeRelation::Contradicts,
    )?;
    let tamper = add_synthetic_edge(&mut snapshot.events[257], EvidenceEdgeRelation::SensorTamper)?;
    let compiled =
        super::compile_capsule(&snapshot, &request(AgentView::Brief)?, &[], &[], &[], &[])?;
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
        orient_deployment(&snapshot, &request(AgentView::Brief)?, &OrientLimits::default())
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
