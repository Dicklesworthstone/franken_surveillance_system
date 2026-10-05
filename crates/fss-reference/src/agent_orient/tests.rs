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

    // The operator cells carry the exact text and state.
    let covered_cell = super::zone_coverage_cell(covered_zone, &anchor)?;
    assert_eq!(covered_cell.knowledge_state(), KnowledgeState::Known);
    assert_eq!(
        covered_cell.statement(),
        format!(
            "source-domain:domain-covered is covered over {window} by 1 retained witness(es) of \
             pipeline generation unknown: no confirmed zone entry other than published \
             candidates. Provenance: {SOURCE_COVERAGE_PROVENANCE}."
        )
    );
    let stale_cell = super::zone_coverage_cell(stale_zone, &anchor)?;
    assert_eq!(stale_cell.knowledge_state(), KnowledgeState::Stale);
    assert_eq!(
        stale_cell.statement(),
        format!("source-domain:domain-stale is stale: {stale_gap}")
    );
    let silent_cell = super::zone_coverage_cell(silent_zone, &anchor)?;
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
