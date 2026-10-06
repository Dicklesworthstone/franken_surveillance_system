//! Tests of the source coverage producer and the stored-witness rule (fss-tch7u).
//!
//! Every integration test drives a real [`ReferenceDeployment`]: capsules of two virtual cameras
//! are staged, the producer derives the witness, a rejected event cites it, the record is retained
//! with its exact approval, and the slot commit makes the run reachable, exactly as `fss-lab quiet`
//! does. Certification is then read from the compiled situation and from the durable `fss orient`
//! reader, which must agree. Epoch and lineage changes and the reserved deletion families have no
//! generic writer, so those kinds are exercised against the shared rule over the real committed
//! history extended by one synthetic batch.
//!
//! Since fss-f8jls every delivered frame is analysed through the model seam
//! ([`analyse_mock_capsule`]) and the rejection is the policy's
//! ([`evaluate_unknown_presence_over_coverage`]); the planted runs write the rejection themselves
//! (as `fss-lab quiet` did before) or analyse only some frames, or under two generations.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::{
    AgentView, BatchId, BudgetVector, CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis,
    Completeness, ContentDigest, ContextAuthority, ContractBasis, ContractBasisRegistryBytes,
    ContractError, CoverageContinuity, CoverageWitness, EventEvidence, EventHypothesis, EventId,
    EventKind, EventState, EvidenceClass, EvidenceDelta, EvidenceDeltaBatch, EvidenceEdgeRelation,
    KnowledgeState, LedgerAnchor, MeaningfulDeltaClass, MissionId, ObjectId, OperationId, Plane,
    PrincipalId, ProbabilityInterval, ResourcePressure, RootAuthoritySpec, SensorCapsule, SensorId,
    SensorSourceBytesSpec, SessionId, StreamId, TimestampNs,
};
use fss_object::ObjectManifest;
use fss_publication::SlotName;

use super::{
    RetainedCoverageRefusal, SourceCoverageError, SourceCoverageInput, SourceCoverageRecord,
    SourceCoverageStatus, StoredCoverage, build_source_coverage, retain_source_coverage,
    verify_retained_coverage,
};
use crate::agent_orient::{
    CLAIM_COVERAGE, OrientLimits, OrientRequest, orient_deployment, read_deployment,
};
use crate::reference_deployment::{
    FAMILY_COVERAGE_WITNESS, FAMILY_PRIVACY_MASK_POLICY, FAMILY_SENSOR_CAPSULE,
};
use crate::{
    ADP_REPLAY_ROW_ID, COVERAGE_ANALYSIS_INCOMPLETE, MockModelResult, MockModelScript,
    MockModelSpec, ReferenceDeployment, ReferenceEventReceipt, ReferenceModelObservation,
    ReferencePolicyAction, ReferencePolicyDecision, ReferenceProjectionSpec, ReferenceSituation,
    ReferenceSituationRequest, ReplayCx, ReplayIoAuthority, analyse_mock_capsule,
    classify_reference_meaningful_delta, evaluate_unknown_presence_over_coverage,
    policy_decision_path, project_reference_situation,
};

type TestResult = Result<(), Box<dyn Error>>;

const SITE: &str = "site:source-coverage";
const FRONT: (&str, &str) = ("cam-front", "front-power-and-network");
const SIDE: (&str, &str) = ("cam-side", "side-power-and-network");
const TICKS: u64 = 5;
const PREDICATE: &str = "no_unknown_person_present";
/// The generation that analyses every frame of a certifying run.
const GEN_A: &str = "mock:model:presence:nothing-found:a";
/// A second generation, for planted mixes.
const GEN_B: &str = "mock:model:presence:nothing-found:b";

fn test_cx(label: &str) -> Result<ReplayCx, Box<dyn Error>> {
    let spec = RootAuthoritySpec {
        trace_id: format!("trace:source-coverage-{label}"),
        operation_id: OperationId::parse(format!("operation:source-coverage-{label}"))?,
        principal: format!("operator:source-coverage-{label}"),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"source-coverage-anchor-universe"),
        generation: 1,
    };
    let root_auth = ContextAuthority::new_root(spec)?;
    let scratch = std::env::temp_dir().join(format!(
        "fss-source-coverage-cx-{label}-{}",
        std::process::id()
    ));
    Ok(ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &root_auth, scratch,
    )?))
}

fn fresh_root(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root =
        std::env::temp_dir().join(format!("fss-source-coverage-{tag}-{}", std::process::id()));
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(root)
}

fn seconds(value: u64) -> Result<TimestampNs, Box<dyn Error>> {
    let nanos = i128::from(value)
        .checked_mul(1_000_000_000)
        .ok_or("time overflow")?;
    Ok(TimestampNs(nanos))
}

fn interval() -> Result<CaptureInterval, Box<dyn Error>> {
    Ok(CaptureInterval::new(seconds(0)?, seconds(TICKS)?)?)
}

/// Stages one capsule of `sensor` at `tick` (and its source payload) and returns it.
fn capsule(
    deployment: &mut ReferenceDeployment,
    staged: &mut Vec<ContentDigest>,
    sensor: &str,
    tick: u64,
    clock_basis: ClockBasis,
) -> Result<SensorCapsule, Box<dyn Error>> {
    let packet = format!("packet:{sensor}:{tick}");
    staged.push(deployment.stage_payload(packet.as_bytes())?);
    let capsule = SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
        capsule_id: CapsuleId::parse(format!("capsule:{sensor}:{tick}"))?,
        sensor_id: SensorId::parse(format!("sensor:{sensor}"))?,
        stream_id: StreamId::parse(format!("stream:{sensor}"))?,
        sequence: tick,
        capture: CaptureInterval::new(seconds(tick)?, seconds(tick + 1)?)?,
        receive_time: seconds(tick + 1)?,
        clock_basis,
        source: packet.as_bytes(),
        frame_count: 1,
        gap_before: false,
    })?;
    staged.push(deployment.stage_payload(&capsule.canonical_bytes())?);
    Ok(capsule)
}

/// Which frames each camera delivers.
type Delivery = fn(&str, u64) -> bool;

fn everything(_: &str, _: u64) -> bool {
    true
}

/// History committed before the witness basis.
type Prelude = fn(&mut ReferenceDeployment, &ReplayCx) -> Result<(), Box<dyn Error>>;

/// Which generation, if any, analyses each delivered frame.
type Analyse = fn(&str, u64) -> Option<&'static str>;

fn all_under_a(_: &str, _: u64) -> Option<&'static str> {
    Some(GEN_A)
}

/// How the run's decision is made from the record and the analyses of its frames.
type Decide = fn(
    &EventId,
    &SourceCoverageRecord,
    Vec<ReferenceModelObservation>,
) -> Result<ReferencePolicyDecision, Box<dyn Error>>;

/// The real policy over the record (fss-f8jls).
fn by_policy(
    event_id: &EventId,
    record: &SourceCoverageRecord,
    observations: Vec<ReferenceModelObservation>,
) -> Result<ReferencePolicyDecision, Box<dyn Error>> {
    Ok(evaluate_unknown_presence_over_coverage(
        event_id.clone(),
        observations,
        record,
    )?)
}

/// The pre-fss-f8jls lab: a rejection written by the caller, citing the witness and no analysis.
fn lab_written(
    event_id: &EventId,
    record: &SourceCoverageRecord,
    _: Vec<ReferenceModelObservation>,
) -> Result<ReferencePolicyDecision, Box<dyn Error>> {
    rejected(event_id, record.witness_object(), &record.witness, 1, None)
}

/// A rejection written by the caller that cites whatever analyses ran exactly as the policy
/// would, bypassing the policy's coverage check: the stored-witness rule must catch it alone.
fn forged(
    event_id: &EventId,
    record: &SourceCoverageRecord,
    observations: Vec<ReferenceModelObservation>,
) -> Result<ReferencePolicyDecision, Box<dyn Error>> {
    let mut evidence = Vec::new();
    let mut model_receipts = Vec::new();
    for observation in &observations {
        let crate::ReferenceModelResult::Mock(result) = &observation.result else {
            return Err("not a mock result".into());
        };
        evidence.push(EventEvidence {
            digest: result.object_digest(),
            class: EvidenceClass::Derived,
            failure_domain: observation.failure_domain.clone(),
            supports: false,
            relation: EvidenceEdgeRelation::Contradicts,
            capsule_digest: Some(result.continuity_digest),
            identity_digest: None,
        });
        model_receipts.push(result.object_digest());
    }
    let mut decision = rejected(event_id, record.witness_object(), &record.witness, 1, None)?;
    decision.event.evidence.splice(0..0, evidence);
    decision.event.model_receipts = model_receipts;
    decision.event.decision_path = policy_decision_path(
        event_id,
        &decision.event.evidence,
        EventState::Rejected,
        ReferencePolicyAction::Hold,
    );
    decision.event.validate()?;
    Ok(decision)
}

/// Everything one run varies.
#[derive(Clone, Copy)]
struct Plan {
    delivery: Delivery,
    retain: bool,
    prelude: Prelude,
    analyse: Analyse,
    decide: Decide,
}

impl Plan {
    fn new(delivery: Delivery, retain: bool) -> Self {
        Self {
            delivery,
            retain,
            prelude: |_, _| Ok(()),
            analyse: all_under_a,
            decide: by_policy,
        }
    }
}

/// One `quiet` run on a real deployment, stopped after the slot commit.
struct Quiet {
    root: PathBuf,
    cx: ReplayCx,
    deployment: Option<ReferenceDeployment>,
    record: SourceCoverageRecord,
    /// Every retained analysis result of the run (the event cites the ones its decision names).
    analyses: Vec<MockModelResult>,
    decision: ReferencePolicyDecision,
    receipt: ReferenceEventReceipt,
    event_id: EventId,
}

impl Quiet {
    /// Runs the lab flow; `retain` false never retains the record (a stored but unretained
    /// witness).
    fn run(tag: &str, delivery: Delivery, retain: bool) -> Result<Self, Box<dyn Error>> {
        Self::run_plan(tag, Plan::new(delivery, retain))
    }

    /// [`Self::run`] after `prelude` commits earlier history: the witness basis is the anchor the
    /// prelude leaves.
    fn run_after(
        tag: &str,
        delivery: Delivery,
        retain: bool,
        prelude: Prelude,
    ) -> Result<Self, Box<dyn Error>> {
        Self::run_plan(
            tag,
            Plan {
                prelude,
                ..Plan::new(delivery, retain)
            },
        )
    }

    fn run_plan(tag: &str, plan: Plan) -> Result<Self, Box<dyn Error>> {
        let Plan {
            delivery,
            retain,
            prelude,
            analyse,
            decide,
        } = plan;
        let root = fresh_root(tag)?;
        let cx = test_cx(tag)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        prelude(&mut deployment, &cx)?;
        let mut staged = Vec::new();
        let mut sources = Vec::new();
        let mut analysed = Vec::new();
        for tick in 0..TICKS {
            for (sensor, domain) in [FRONT, SIDE] {
                if delivery(sensor, tick) {
                    let capsule = capsule(
                        &mut deployment,
                        &mut staged,
                        sensor,
                        tick,
                        ClockBasis::DeviceMonotonic,
                    )?;
                    if let Some(generation) = analyse(sensor, tick) {
                        analysed.push((generation, domain, capsule.clone()));
                    }
                    sources.push((domain.to_owned(), capsule));
                }
            }
        }
        let record = build_source_coverage(&SourceCoverageInput {
            basis: deployment.current_anchor().clone(),
            interval: interval()?,
            negative_predicate: PREDICATE,
            authorized_domain: BTreeSet::from([FRONT.1.to_owned(), SIDE.1.to_owned()]),
            sources: sources
                .iter()
                .map(|(domain, capsule)| (domain.clone(), capsule))
                .collect(),
        })?;
        let witness_object = deployment.stage_payload(&record.witness.canonical_bytes())?;
        assert_eq!(witness_object, record.witness_object());
        staged.push(witness_object);
        // Each analysed frame goes through the model seam; its result is retained with the run.
        let mut analyses = Vec::new();
        let mut observations = Vec::new();
        for (generation, domain, capsule) in &analysed {
            let spec = MockModelSpec::new(*generation, MockModelScript::NothingFound)?;
            let result = analyse_mock_capsule(&spec, capsule);
            let digest = deployment.stage_payload(&result.canonical_bytes())?;
            assert_eq!(digest, result.object_digest());
            staged.push(digest);
            observations.push(ReferenceModelObservation::new(
                result.clone(),
                *domain,
                capsule.capture,
            )?);
            analyses.push(result);
        }
        let event_id = EventId::parse(format!("event:source-coverage:{tag}"))?;
        let decision = decide(&event_id, &record, observations)?;
        let receipt = deployment.publish_event(&decision, &cx)?;
        staged.extend([
            receipt.event_root,
            receipt.event_object_digest,
            receipt.event_revision_digest,
            receipt.lineage_tamper_status.canonical_digest(),
        ]);
        if retain {
            let status =
                retain_source_coverage(&mut deployment, &record, record.approval_digest(), &cx)?;
            assert_eq!(status, SourceCoverageStatus::Retained);
            staged.push(record.digest());
        }
        commit_slot(&mut deployment, "slot-sources", staged, &cx)?;
        Ok(Self {
            root,
            cx,
            deployment: Some(deployment),
            record,
            analyses,
            decision,
            receipt,
            event_id,
        })
    }

    fn deployment(&mut self) -> Result<&mut ReferenceDeployment, Box<dyn Error>> {
        if self.deployment.is_none() {
            self.deployment = Some(ReferenceDeployment::reopen(&self.root, SITE, &self.cx)?);
        }
        self.deployment
            .as_mut()
            .ok_or_else(|| "no deployment".into())
    }

    /// The committed history and head.
    fn history(&mut self) -> Result<(Vec<EvidenceDeltaBatch>, LedgerAnchor), Box<dyn Error>> {
        let deployment = self.deployment()?;
        Ok((
            deployment.ledger().batches().to_vec(),
            deployment.current_anchor().clone(),
        ))
    }

    /// The compiled situation offered the stored witness and (when `record`) its record.
    fn situation(&mut self, record: bool) -> Result<ReferenceSituation, Box<dyn Error>> {
        let witness = self.record.witness.clone();
        let stored = self.record.clone();
        self.situation_with(&witness, record.then_some(&stored))
    }

    /// The compiled situation offered `witness` and `record`.
    fn situation_with(
        &mut self,
        witness: &CoverageWitness,
        record: Option<&SourceCoverageRecord>,
    ) -> Result<ReferenceSituation, Box<dyn Error>> {
        self.situation_offered(Some(witness), record)
    }

    /// The compiled situation offered no coverage at all.
    fn situation_without_coverage(&mut self) -> Result<ReferenceSituation, Box<dyn Error>> {
        self.situation_offered(None, None)
    }

    fn situation_offered(
        &mut self,
        witness: Option<&CoverageWitness>,
        record: Option<&SourceCoverageRecord>,
    ) -> Result<ReferenceSituation, Box<dyn Error>> {
        self.situation_revision(witness, record, 1)
    }

    /// [`Self::situation_offered`] at situation `revision`.
    fn situation_revision(
        &mut self,
        witness: Option<&CoverageWitness>,
        record: Option<&SourceCoverageRecord>,
        revision: u64,
    ) -> Result<ReferenceSituation, Box<dyn Error>> {
        let decision = self.decision.clone();
        let receipt = self.receipt.clone();
        let analyses = self.analyses.clone();
        let cx = test_cx("compile")?;
        let request = ReferenceSituationRequest {
            mission_id: MissionId::parse("mission:source-coverage")?,
            session_id: SessionId::parse("session:source-coverage")?,
            principal_id: PrincipalId::parse("principal:source-coverage")?,
            objective_id: "objective:source-coverage".to_owned(),
            revision,
            contract_basis: ContractBasis::from_registry_bytes(
                ContractBasisRegistryBytes::new(
                    b"schemas",
                    b"operations",
                    b"views",
                    b"capabilities",
                    b"errors",
                    b"costs",
                    "fss/1",
                )
                .with_accepted_nightly("nightly-2026-08-31"),
            ),
            previous_anchor: None,
            predecessor_publication: None,
            decision: &decision,
            event_receipt: &receipt,
            alert_plan: None,
            alert_outcome: None,
            coverage_witness: witness,
            coverage_record: record.map(|record| StoredCoverage {
                record,
                analyses: &analyses,
            }),
            available_capabilities: BTreeSet::from(["capability:evidence.query".to_owned()]),
            created_at: seconds(TICKS)?,
        };
        Ok(self.deployment()?.compile_situation(request, &cx)?)
    }

    /// What the durable `fss orient` reader says, on the committed bytes (the deployment is
    /// closed first, as the lab does).
    fn durable(&mut self) -> Result<Durable, Box<dyn Error>> {
        self.deployment = None;
        let limits = OrientLimits::default();
        let snapshot = read_deployment(&self.root, &limits)?;
        let orientation = orient_deployment(
            &snapshot,
            &OrientRequest {
                view: AgentView::EpistemicMap,
                principal: PrincipalId::parse("principal:source-coverage")?,
                budget_tokens: None,
            },
            &limits,
        )?;
        let frame = &orientation.publication.situation.capsule.frame;
        let cell_id = format!(
            "claim:event:{}:absence-certification",
            self.event_id.as_str()
        );
        Ok(Durable {
            site: frame
                .knowledge_cells
                .iter()
                .find(|cell| cell.claim_id() == CLAIM_COVERAGE)
                .map(|cell| cell.knowledge_state()),
            uncertified_world: frame
                .world_envelope
                .adversarial_residuals
                .iter()
                .any(|world| {
                    world.protected && world.world_id == "world:events:absence-uncertified"
                }),
            absence_cell: frame
                .knowledge_cells
                .iter()
                .find(|cell| cell.claim_id() == cell_id)
                .map(|cell| (cell.knowledge_state(), cell.statement().to_owned())),
            absence_evidence: frame
                .knowledge_cells
                .iter()
                .find(|cell| cell.claim_id() == cell_id)
                .map(|cell| cell.evidence_digests())
                .unwrap_or_default(),
            retained: snapshot
                .retained_absences
                .get(self.event_id.as_str())
                .map(|absence| absence.record_digest),
        })
    }

    fn cleanup(self) {
        let root = self.root.clone();
        drop(self);
        let _ = fs::remove_dir_all(root);
    }
}

/// The durable reader's absence verdict.
#[derive(Debug)]
struct Durable {
    site: Option<KnowledgeState>,
    uncertified_world: bool,
    absence_cell: Option<(KnowledgeState, String)>,
    /// Evidence the durable absence cell cites.
    absence_evidence: Vec<ContentDigest>,
    retained: Option<ContentDigest>,
}

impl Durable {
    fn certified(&self) -> bool {
        self.site == Some(KnowledgeState::Known)
            && !self.uncertified_world
            && self.retained.is_some()
            && self
                .absence_cell
                .as_ref()
                .is_some_and(|(state, _)| *state == KnowledgeState::Known)
    }
}

/// The situation's absence verdict: (cell state, residual world kept, statement).
fn situation_absence(
    situation: &ReferenceSituation,
    event_id: &EventId,
) -> (Option<KnowledgeState>, bool, String) {
    let frame = &situation.capsule.frame;
    let cell_id = format!("claim:event:{}:absence-certification", event_id.as_str());
    let world_id = format!("world:event:{}:absence-uncertified", event_id.as_str());
    let cell = frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id() == cell_id);
    (
        cell.map(|cell| cell.knowledge_state()),
        frame
            .world_envelope
            .adversarial_residuals
            .iter()
            .any(|world| world.protected && world.world_id == world_id),
        cell.map(|cell| cell.statement().to_owned())
            .unwrap_or_default(),
    )
}

/// Evidence the situation's absence cell cites.
fn situation_absence_evidence(
    situation: &ReferenceSituation,
    event_id: &EventId,
) -> Vec<ContentDigest> {
    let cell_id = format!("claim:event:{}:absence-certification", event_id.as_str());
    situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id() == cell_id)
        .map(|cell| cell.evidence_digests())
        .unwrap_or_default()
}

fn situation_certified(situation: &ReferenceSituation, event_id: &EventId) -> bool {
    let (cell, world, _) = situation_absence(situation, event_id);
    match (cell, world) {
        (Some(KnowledgeState::Known), false) => true,
        (Some(KnowledgeState::Known), true) => false,
        _ => {
            assert!(
                world,
                "an uncertified absence must keep its protected world"
            );
            false
        }
    }
}

/// A rejected decision citing `witness_object` as contradicting evidence of every observed domain.
fn rejected(
    event_id: &EventId,
    witness_object: ContentDigest,
    witness: &CoverageWitness,
    revision: u64,
    supersedes: Option<ContentDigest>,
) -> Result<ReferencePolicyDecision, Box<dyn Error>> {
    let evidence: Vec<EventEvidence> = witness
        .observed_domain
        .iter()
        .map(|domain| EventEvidence {
            digest: witness_object,
            class: EvidenceClass::Derived,
            failure_domain: domain.clone(),
            supports: false,
            relation: EvidenceEdgeRelation::Contradicts,
            capsule_digest: None,
            identity_digest: None,
        })
        .collect();
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_string(),
        event_id: event_id.clone(),
        revision,
        supersedes,
        state: EventState::Rejected,
        kind: EventKind::UnknownPresence,
        interval: interval()?,
        uncertainty_reason: None,
        zone_ids: Vec::new(),
        track_ids: Vec::new(),
        probability: ProbabilityInterval::new(0.0, 1.0)?,
        decision_path: policy_decision_path(
            event_id,
            &evidence,
            EventState::Rejected,
            ReferencePolicyAction::Hold,
        ),
        evidence,
        model_receipts: Vec::new(),
    };
    event.validate()?;
    Ok(ReferencePolicyDecision {
        event,
        action: ReferencePolicyAction::Hold,
    })
}

fn commit_slot(
    deployment: &mut ReferenceDeployment,
    slot: &str,
    mut staged: Vec<ContentDigest>,
    cx: &ReplayCx,
) -> Result<(), Box<dyn Error>> {
    staged.sort_unstable();
    staged.dedup();
    let manifest = ObjectManifest::new(slot, staged, None)?;
    deployment.publish_and_commit(&SlotName::parse(slot)?, &manifest, interval()?, cx)?;
    Ok(())
}

fn delta(
    family: &str,
    object: &str,
    payload: ContentDigest,
) -> Result<EvidenceDelta, Box<dyn Error>> {
    Ok(EvidenceDelta {
        delta_id: format!("delta:{object}"),
        family: family.to_owned(),
        object_id: ObjectId::parse(format!("object:{object}"))?,
        prior_generation: None,
        new_generation: 1,
        validity: interval()?,
        plane: Plane::Authority,
        payload_digest: payload,
        witness_digest: None,
        operation_id: None,
    })
}

fn assert_certified(quiet: &mut Quiet) -> TestResult {
    let situation = quiet.situation(true)?;
    let (cell, world, statement) = situation_absence(&situation, &quiet.event_id);
    assert_eq!(cell, Some(KnowledgeState::Known));
    assert!(!world);
    let record = quiet.record.digest();
    // The witness and the record that retains it are named: in the cell and in the proof roots
    // the sealed handoff carries.
    assert!(statement.contains(&record.to_string()), "{statement}");
    assert!(statement.contains("not physical absence"), "{statement}");
    assert!(situation.proof_roots.contains(&record));
    assert!(
        situation
            .proof_roots
            .contains(&quiet.record.witness.witness_digest())
    );

    // Both cells cite every frame's analysis result, so the certification hydrates from the cell
    // (fss-f8jls review D4).
    let receipts = quiet.decision.event.model_receipts.clone();
    assert!(!receipts.is_empty());
    let cited = situation_absence_evidence(&situation, &quiet.event_id);
    for receipt in &receipts {
        assert!(cited.contains(receipt), "situation cell omits {receipt}");
    }

    let durable = quiet.durable()?;
    assert!(durable.certified(), "{durable:?}");
    assert_eq!(durable.retained, Some(record));
    for receipt in &receipts {
        assert!(
            durable.absence_evidence.contains(receipt),
            "durable cell omits {receipt}"
        );
    }
    let (_, statement) = durable.absence_cell.ok_or("no durable absence cell")?;
    assert!(statement.contains(&record.to_string()), "{statement}");
    Ok(())
}

/// Neither reader certifies; the protected world survives in both.
fn assert_not_certified(quiet: &mut Quiet, reason: &str) -> TestResult {
    let situation = quiet.situation(true)?;
    let (cell, world, statement) = situation_absence(&situation, &quiet.event_id);
    assert_eq!(cell, Some(KnowledgeState::Unknown), "{reason}");
    assert!(world, "{reason}");
    assert!(statement.contains(reason), "{reason}: {statement}");
    assert!(!situation.proof_roots.contains(&quiet.record.digest()));
    let durable = quiet.durable()?;
    assert!(!durable.certified(), "{reason}: {durable:?}");
    assert!(durable.uncertified_world, "{reason}");
    assert_ne!(durable.site, Some(KnowledgeState::Known), "{reason}");
    assert!(durable.absence_cell.is_none(), "{reason}");
    assert!(durable.retained.is_none(), "{reason}");
    Ok(())
}

// --- producer -----------------------------------------------------------------------------------

#[test]
fn the_producer_derives_a_complete_witness_only_from_continuous_delivery() -> TestResult {
    let quiet = Quiet::run("derive", everything, false)?;
    let witness = &quiet.record.witness;
    assert!(witness.certifies_absence());
    assert_eq!(witness.anchor.commit_sequence, 0);
    assert_eq!(witness.observed_domain, witness.authorized_domain);
    assert_eq!(quiet.record.frames.len(), 10);
    // Exact bytes round-trip and are pinned to their digest.
    let bytes = quiet.record.to_bytes();
    assert!(SourceCoverageRecord::is_source_record(&bytes));
    assert_eq!(
        SourceCoverageRecord::from_bytes(&bytes, quiet.record.digest())?,
        quiet.record
    );
    assert_eq!(
        SourceCoverageRecord::from_bytes(&bytes, ContentDigest::sha256(b"other")),
        Err(ContractError::DigestMismatch)
    );
    // A record carrying a witness its frames do not support never decodes.
    let mut forged = quiet.record.clone();
    forged.frames.retain(|frame| frame.failure_domain != SIDE.1);
    let bytes = forged.to_bytes();
    assert_eq!(
        SourceCoverageRecord::from_bytes(&bytes, ContentDigest::sha256(&bytes)),
        Err(ContractError::CoverageUncertified)
    );
    quiet.cleanup();
    Ok(())
}

#[test]
fn a_silent_tick_or_camera_yields_a_gapped_partial_witness() -> TestResult {
    fn one_tick(sensor: &str, tick: u64) -> bool {
        !(sensor == SIDE.0 && tick == 2)
    }
    fn whole(sensor: &str, _: u64) -> bool {
        sensor != SIDE.0
    }
    for (tag, delivery) in [("gap-tick", one_tick as Delivery), ("gap-camera", whole)] {
        let quiet = Quiet::run(tag, delivery, false)?;
        let witness = &quiet.record.witness;
        assert_eq!(witness.continuity, CoverageContinuity::Gapped, "{tag}");
        assert_eq!(witness.completeness, Completeness::Partial, "{tag}");
        assert_eq!(
            witness.observed_domain,
            BTreeSet::from([FRONT.1.to_owned()]),
            "{tag}"
        );
        assert!(!witness.certifies_absence(), "{tag}");
        quiet.cleanup();
    }
    Ok(())
}

#[test]
fn file_import_capsules_are_never_a_continuity_source() -> TestResult {
    // A file import's capsules carry an estimated clock (`ingest::file_adapter`); its session
    // never reaches ContinuityVerified (AbsenceClaimForbidden), and the producer refuses it too.
    let root = fresh_root("estimated")?;
    let cx = test_cx("estimated")?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let mut staged = Vec::new();
    let mut capsules = Vec::new();
    for tick in 0..TICKS {
        capsules.push(capsule(
            &mut deployment,
            &mut staged,
            FRONT.0,
            tick,
            ClockBasis::Estimated,
        )?);
    }
    let built = build_source_coverage(&SourceCoverageInput {
        basis: deployment.current_anchor().clone(),
        interval: interval()?,
        negative_predicate: PREDICATE,
        authorized_domain: BTreeSet::from([FRONT.1.to_owned()]),
        sources: capsules
            .iter()
            .map(|capsule| (FRONT.1.to_owned(), capsule))
            .collect(),
    });
    assert_eq!(built, Err(ContractError::CoverageUncertified));
    drop(deployment);
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn retention_requires_the_exact_approval_and_is_idempotent() -> TestResult {
    let mut quiet = Quiet::run("approval", everything, false)?;
    let record = quiet.record.clone();
    let cx = test_cx("approval-retain")?;
    let stale = ContentDigest::sha256(b"stale approval");
    let refused = retain_source_coverage(quiet.deployment()?, &record, stale, &cx);
    assert!(matches!(refused, Err(SourceCoverageError::StaleApproval(digest)) if digest == stale));
    assert_eq!(
        refused.map_err(|error| error.stable_id()).err(),
        Some("ERR-COVERAGE-APPROVAL-STALE-001")
    );
    let approval = record.approval_digest();
    assert_eq!(
        retain_source_coverage(quiet.deployment()?, &record, approval, &cx)?,
        SourceCoverageStatus::Retained
    );
    let head = quiet.deployment()?.current_anchor().clone();
    assert_eq!(
        retain_source_coverage(quiet.deployment()?, &record, approval, &cx)?,
        SourceCoverageStatus::AlreadyRetained
    );
    assert_eq!(*quiet.deployment()?.current_anchor(), head);
    quiet.cleanup();
    Ok(())
}

#[test]
fn retention_refuses_a_source_the_spool_does_not_hold_exactly() -> TestResult {
    let mut quiet = Quiet::run("custody", everything, false)?;
    let mut record = quiet.record.clone();
    // A frame whose capsule digest names bytes the spool never held.
    if let Some(frame) = record.frames.first_mut() {
        frame.capsule_digest = ContentDigest::sha256(b"never staged");
    }
    record
        .frames
        .sort_by(|a, b| a.order_key().cmp(&b.order_key()));
    let cx = test_cx("custody-retain")?;
    let refused =
        retain_source_coverage(quiet.deployment()?, &record, record.approval_digest(), &cx);
    assert!(matches!(
        refused,
        Err(SourceCoverageError::SourceMismatch(_))
    ));
    quiet.cleanup();
    Ok(())
}

// --- certification ------------------------------------------------------------------------------

#[test]
fn a_stored_witness_with_only_bookkeeping_after_it_is_certified_by_both_readers() -> TestResult {
    let mut quiet = Quiet::run("bookkeeping", everything, true)?;
    // Basis commit 0; after it: the event publication (1), the record retention (2) and the slot
    // commit of the run's own sources (3). All bookkeeping.
    assert_eq!(quiet.record.witness.anchor.commit_sequence, 0);
    assert_eq!(quiet.deployment()?.current_anchor().commit_sequence, 3);
    // Without the record, the stored witness is refused exactly as before (anchor equality).
    let situation = quiet.situation(false)?;
    let (cell, world, statement) = situation_absence(&situation, &quiet.event_id);
    assert_eq!(cell, Some(KnowledgeState::Unknown));
    assert!(world);
    assert!(
        statement.contains("conflicts with current anchor"),
        "{statement}"
    );
    assert_certified(&mut quiet)?;
    quiet.cleanup();
    Ok(())
}

#[test]
fn a_sensor_capsule_commit_of_the_witness_own_source_is_bookkeeping() -> TestResult {
    let mut quiet = Quiet::run("own-capsule", everything, true)?;
    let own = quiet
        .record
        .frames
        .first()
        .ok_or("no frame")?
        .capsule_digest;
    let cx = test_cx("own-capsule-append")?;
    quiet.deployment()?.append_batch(
        BatchId::parse("batch:own-capsule")?,
        vec![delta(FAMILY_SENSOR_CAPSULE, "capsule:own", own)?],
        Vec::new(),
        &cx,
    )?;
    assert_certified(&mut quiet)?;
    quiet.cleanup();
    Ok(())
}

#[test]
fn a_new_capsule_after_the_basis_invalidates_both_readers() -> TestResult {
    let mut quiet = Quiet::run("new-capsule", everything, true)?;
    let cx = test_cx("new-capsule-append")?;
    let mut staged = Vec::new();
    let late = capsule(
        quiet.deployment()?,
        &mut staged,
        FRONT.0,
        2,
        ClockBasis::HostMonotonic,
    )?;
    let digest = ContentDigest::sha256(&late.canonical_bytes());
    quiet.deployment()?.append_batch(
        BatchId::parse("batch:late-capsule")?,
        vec![delta(FAMILY_SENSOR_CAPSULE, "capsule:late", digest)?],
        Vec::new(),
        &cx,
    )?;
    commit_slot(quiet.deployment()?, "slot-late", staged, &cx)?;
    assert_not_certified(&mut quiet, "coverage-relevant commit 4 (sensor_capsule")?;
    quiet.cleanup();
    Ok(())
}

#[test]
fn an_observation_published_after_the_basis_invalidates_both_readers() -> TestResult {
    let mut quiet = Quiet::run("observation", everything, true)?;
    let cx = test_cx("observation-slot")?;
    // A model finding staged and made reachable by a later slot commit: an observation the
    // witness never accounted for.
    let finding = quiet
        .deployment()?
        .stage_payload(b"model finding: person-like at cam-front tick 3")?;
    commit_slot(quiet.deployment()?, "slot-finding", vec![finding], &cx)?;
    assert_not_certified(&mut quiet, "coverage-relevant commit 4 (children")?;
    quiet.cleanup();
    Ok(())
}

#[test]
fn a_revision_of_the_event_invalidates_both_readers() -> TestResult {
    let mut quiet = Quiet::run("revision", everything, true)?;
    let cx = test_cx("revision-publish")?;
    // Revision 2 of the same event, still rejected and still citing the witness and every
    // analysis: the witness basis now precedes two publications of the event, so revision 1's is
    // not bookkeeping.
    let mut decision = quiet.decision.clone();
    decision.event.revision = 2;
    decision.event.supersedes = Some(quiet.decision.event.revision_digest());
    decision.event.validate()?;
    let receipt = quiet.deployment()?.publish_event(&decision, &cx)?;
    commit_slot(
        quiet.deployment()?,
        "slot-revision",
        vec![
            receipt.event_root,
            receipt.event_object_digest,
            receipt.event_revision_digest,
            receipt.lineage_tamper_status.canonical_digest(),
        ],
        &cx,
    )?;
    quiet.decision = decision;
    quiet.receipt = receipt;
    assert_not_certified(&mut quiet, "(event_revision delta:event:")?;
    quiet.cleanup();
    Ok(())
}

#[test]
fn another_event_published_after_the_basis_invalidates_both_readers() -> TestResult {
    let mut quiet = Quiet::run("other-event", everything, true)?;
    let cx = test_cx("other-event-publish")?;
    let other = EventId::parse("event:source-coverage:other")?;
    let witness_object = quiet.record.witness_object();
    let decision = rejected(&other, witness_object, &quiet.record.witness, 1, None)?;
    quiet.deployment()?.publish_event(&decision, &cx)?;
    let situation = quiet.situation(true)?;
    assert!(!situation_certified(&situation, &quiet.event_id));
    let (_, _, statement) = situation_absence(&situation, &quiet.event_id);
    assert!(statement.contains("(event_revision"), "{statement}");
    // The durable reader holds two events; neither is certified.
    quiet.deployment = None;
    let snapshot = read_deployment(&quiet.root, &OrientLimits::default())?;
    assert!(snapshot.retained_absences.is_empty());
    quiet.cleanup();
    Ok(())
}

#[test]
fn a_privacy_mask_change_after_the_basis_invalidates_both_readers() -> TestResult {
    let mut quiet = Quiet::run("mask", everything, true)?;
    let cx = test_cx("mask-append")?;
    let policy = quiet
        .deployment()?
        .stage_payload(b"privacy mask policy over front-power-and-network")?;
    quiet.deployment()?.append_batch(
        BatchId::parse("batch:mask")?,
        vec![delta(
            FAMILY_PRIVACY_MASK_POLICY,
            "privacy-mask:front",
            policy,
        )?],
        vec![policy],
        &cx,
    )?;
    assert_not_certified(&mut quiet, "(privacy_mask_policy")?;
    quiet.cleanup();
    Ok(())
}

#[test]
fn another_coverage_record_after_the_basis_invalidates_both_readers() -> TestResult {
    let mut quiet = Quiet::run("second-record", everything, true)?;
    // A second, re-anchored record of the same frames retained later: a re-anchored copy. The
    // event does not cite it, and its retention is a coverage-relevant commit for the first.
    let mut copy = quiet.record.clone();
    copy.witness.anchor = quiet.deployment()?.current_anchor().clone();
    copy.validate()?;
    let cx = test_cx("second-record-retain")?;
    retain_source_coverage(quiet.deployment()?, &copy, copy.approval_digest(), &cx)?;
    commit_slot(quiet.deployment()?, "slot-copy", vec![copy.digest()], &cx)?;
    let (batches, head) = quiet.history()?;
    assert_eq!(
        verify_retained_coverage(
            &copy,
            Some(&quiet.decision.event),
            &quiet.analyses,
            &batches,
            &head
        ),
        Err(RetainedCoverageRefusal::WitnessNotCited)
    );
    // Nor does the later basis hide what preceded it: the event publication at commit 1 bears on
    // the interval and is not the copy's bookkeeping.
    assert!(matches!(
        verify_retained_coverage(&copy, None, &[], &batches, &head),
        Err(RetainedCoverageRefusal::CoverageRelevantCommit { sequence: 1, .. })
    ));
    assert_not_certified(&mut quiet, "(coverage_witness delta:coverage:source:")?;
    quiet.cleanup();
    Ok(())
}

#[test]
fn a_reanchored_copy_offered_with_the_stored_record_is_refused() -> TestResult {
    let mut quiet = Quiet::run("reanchored", everything, true)?;
    let (batches, head) = quiet.history()?;
    // A copy re-anchored to an earlier commit than the head (so anchor equality does not apply)
    // and offered beside the stored record: the record does not retain it.
    let mut copy = quiet.record.witness.clone();
    copy.anchor = batches.first().ok_or("no batch")?.new_anchor.clone();
    assert_ne!(copy.anchor, head);
    let stored = quiet.record.clone();
    let situation = quiet.situation_with(&copy, Some(&stored))?;
    let (cell, world, statement) = situation_absence(&situation, &quiet.event_id);
    assert_eq!(cell, Some(KnowledgeState::Unknown));
    assert!(world);
    assert!(
        statement.contains("no committed coverage_witness record"),
        "{statement}"
    );
    quiet.cleanup();
    Ok(())
}

// --- an unstored witness at the current anchor (fss-plt5h) ---------------------------------------

/// The run's witness re-anchored to the exact current anchor, to be offered without its record:
/// the path that, before fss-plt5h, certified on anchor equality alone.
fn current_anchor_copy(quiet: &mut Quiet) -> Result<CoverageWitness, Box<dyn Error>> {
    let (_, head) = quiet.history()?;
    let mut copy = quiet.record.witness.clone();
    copy.anchor = head;
    // Intrinsically the copy certifies, so only the missing stored route can refuse it.
    assert!(copy.certifies_absence());
    Ok(copy)
}

/// The compiled situation refuses `copy` offered without a record and states the typed refusal:
/// the absence cell is `Unknown` (never dropped, never Known), the protected world survives, the
/// situation's unknowns carry the same reason, and neither the witness nor the record becomes a
/// proof root.
fn assert_unstored_refused(quiet: &mut Quiet, copy: &CoverageWitness) -> TestResult {
    let situation = quiet.situation_with(copy, None)?;
    let (cell, world, statement) = situation_absence(&situation, &quiet.event_id);
    assert_eq!(cell, Some(KnowledgeState::Unknown), "{statement}");
    assert!(world, "{statement}");
    let refusal = RetainedCoverageRefusal::WitnessNotStored.to_string();
    assert!(statement.contains(&refusal), "{statement}");
    assert!(
        situation
            .capsule
            .frame
            .unknown
            .iter()
            .any(|unknown| unknown.contains(&refusal)),
        "the refusal is not stated in the situation's unknowns: {:?}",
        situation.capsule.frame.unknown
    );
    assert!(!situation.proof_roots.contains(&copy.witness_digest()));
    assert!(!situation.proof_roots.contains(&quiet.record.digest()));
    Ok(())
}

/// Planted negative (fss-plt5h): the pre-fss-f8jls lab rejection (every frame delivered, none
/// analysed) with its witness re-anchored to the current anchor and offered without its record.
/// Before the fix the compiler certified it on anchor equality alone.
#[test]
fn a_current_anchor_witness_without_analysis_does_not_certify() -> TestResult {
    let mut quiet = Quiet::run_plan(
        "current-anchor-unanalysed",
        Plan {
            analyse: |_, _| None,
            decide: lab_written,
            ..Plan::new(everything, true)
        },
    )?;
    assert!(quiet.analyses.is_empty());
    assert_eq!(quiet.decision.event.state, EventState::Rejected);
    let copy = current_anchor_copy(&mut quiet)?;
    assert_unstored_refused(&mut quiet, &copy)?;
    // Offered beside the stored record, the copy is not what the record retains.
    let stored = quiet.record.clone();
    let situation = quiet.situation_with(&copy, Some(&stored))?;
    let (cell, world, statement) = situation_absence(&situation, &quiet.event_id);
    assert_eq!(cell, Some(KnowledgeState::Unknown));
    assert!(world);
    assert!(
        statement.contains("no committed coverage_witness record"),
        "{statement}"
    );
    // And the stored route itself refuses the unanalysed run.
    assert_not_certified(&mut quiet, "delivered but never analysed")?;
    quiet.cleanup();
    Ok(())
}

/// Every frame analysed and the policy's rejection: the unstored current-anchor copy is still
/// refused (a bare witness names no frame its analyses could be bound to), while the same run's
/// stored witness, verified with its hydrated analyses, certifies. The stored route is the only
/// route.
#[test]
fn a_current_anchor_witness_with_every_frame_analysed_certifies_only_through_its_record()
-> TestResult {
    let mut quiet = Quiet::run("current-anchor-analysed", everything, true)?;
    assert_eq!(quiet.decision.event.state, EventState::Rejected);
    assert_eq!(
        quiet.decision.event.model_receipts.len(),
        quiet.record.frames.len()
    );
    let copy = current_anchor_copy(&mut quiet)?;
    assert_unstored_refused(&mut quiet, &copy)?;
    assert_certified(&mut quiet)?;
    quiet.cleanup();
    Ok(())
}

/// Analysis of all but one frame, under a forged rejection: the unstored current-anchor copy is
/// refused, as is the stored route (naming the unanalysed frame).
#[test]
fn a_current_anchor_witness_with_partial_analysis_does_not_certify() -> TestResult {
    let mut quiet = Quiet::run_plan(
        "current-anchor-partial",
        Plan {
            analyse: all_but_one_frame,
            decide: forged,
            ..Plan::new(everything, true)
        },
    )?;
    assert_eq!(quiet.decision.event.state, EventState::Rejected);
    assert_eq!(quiet.decision.event.model_receipts.len(), 9);
    let copy = current_anchor_copy(&mut quiet)?;
    assert_unstored_refused(&mut quiet, &copy)?;
    assert_not_certified(&mut quiet, "has no cited analysed-nothing model result")?;
    quiet.cleanup();
    Ok(())
}

/// The meaningful delta of absence certification, from real producers: offering an unstored
/// current-anchor witness leaves the absence claim `Unknown`, while the stored, fully analysed
/// witness turns it Known and the change is reported as a material state change.
#[test]
fn only_the_stored_route_moves_absence_to_known_in_a_meaningful_delta() -> TestResult {
    let mut quiet = Quiet::run("current-anchor-delta", everything, true)?;
    let copy = current_anchor_copy(&mut quiet)?;
    let stored = quiet.record.clone();
    let spec = projection_spec()?;
    let basis = project_reference_situation(quiet.situation_revision(None, None, 1)?, &spec)?;
    let unstored =
        project_reference_situation(quiet.situation_revision(Some(&copy), None, 2)?, &spec)?;
    let certified = project_reference_situation(
        quiet.situation_revision(Some(&stored.witness), Some(&stored), 2)?,
        &spec,
    )?;
    let cell_id = format!(
        "claim:event:{}:absence-certification",
        quiet.event_id.as_str()
    );
    let absence_state = |publication: &crate::ReferenceSituationPublication| {
        publication
            .situation
            .capsule
            .frame
            .knowledge_cells
            .iter()
            .find(|cell| cell.claim_id() == cell_id)
            .map(|cell| cell.knowledge_state())
    };
    assert_eq!(absence_state(&basis), Some(KnowledgeState::Unknown));
    assert_eq!(absence_state(&unstored), Some(KnowledgeState::Unknown));
    assert_eq!(absence_state(&certified), Some(KnowledgeState::Known));
    let delta = classify_reference_meaningful_delta(&basis, &certified)?;
    assert!(
        delta.classes.contains(&MeaningfulDeltaClass::MaterialState),
        "{:?}",
        delta.classes
    );
    quiet.cleanup();
    Ok(())
}

fn projection_spec() -> Result<ReferenceProjectionSpec, Box<dyn Error>> {
    Ok(ReferenceProjectionSpec {
        view_id: "AVIEW-001".to_owned(),
        available_resources: BudgetVector::builder()
            .latency_ms(10_000)
            .tokens(20_000)
            .bytes(1_000_000)
            .model_calls(10)
            .cpu_millis(10_000)
            .accelerator_millis(10_000)
            .energy_millijoules(1_000_000)
            .network_bytes(1_000_000)
            .storage_operations(10_000)
            .privacy_exposure(10.0)
            .operator_attention_seconds(1_000.0)
            .build()?,
        reserved_resources: BudgetVector::builder()
            .latency_ms(100)
            .tokens(100)
            .bytes(1_000)
            .storage_operations(1)
            .build()?,
        pressure: ResourcePressure::Nominal,
        degraded_dimensions: BTreeSet::new(),
        target_tokens: 10_000,
    })
}

#[test]
fn a_missing_record_does_not_certify() -> TestResult {
    // The witness is stored and cited, but no record retains it.
    let mut quiet = Quiet::run("missing", everything, false)?;
    let situation = quiet.situation(true)?;
    let (cell, world, statement) = situation_absence(&situation, &quiet.event_id);
    assert_eq!(cell, Some(KnowledgeState::Unknown));
    assert!(world);
    assert!(
        statement.contains("no committed coverage_witness record"),
        "{statement}"
    );
    let durable = quiet.durable()?;
    assert!(!durable.certified());
    assert_eq!(durable.site, Some(KnowledgeState::NotObservable));
    assert!(durable.uncertified_world);
    quiet.cleanup();
    Ok(())
}

#[test]
fn a_tampered_record_does_not_certify() -> TestResult {
    let mut quiet = Quiet::run("tampered", everything, true)?;
    // Offered in memory with one frame edited: its digest is not the committed one.
    let mut tampered = quiet.record.clone();
    if let Some(frame) = tampered.frames.last_mut() {
        frame.sequence += 100;
    }
    let (batches, head) = quiet.history()?;
    assert_eq!(
        verify_retained_coverage(
            &tampered,
            Some(&quiet.decision.event),
            &quiet.analyses,
            &batches,
            &head
        ),
        Err(RetainedCoverageRefusal::NotRetained)
    );
    // On disk: the committed record's bytes are damaged; the durable reader rehashes every object
    // and refuses the root rather than certify from them.
    let digest = quiet.record.digest();
    let path = quiet.deployment()?.publisher().spool().object_path(digest);
    quiet.deployment = None;
    let mut bytes = fs::read(&path)?;
    if let Some(byte) = bytes.last_mut() {
        *byte ^= 0x01;
    }
    fs::write(&path, bytes)?;
    assert!(read_deployment(&quiet.root, &OrientLimits::default()).is_err());
    quiet.cleanup();
    Ok(())
}

#[test]
fn a_gapped_or_partial_stored_witness_does_not_certify() -> TestResult {
    fn one_tick(sensor: &str, tick: u64) -> bool {
        !(sensor == SIDE.0 && tick == 2)
    }
    fn whole(sensor: &str, _: u64) -> bool {
        sensor != SIDE.0
    }
    for (tag, delivery) in [
        ("stored-gap-tick", one_tick as Delivery),
        ("stored-gap-camera", whole),
    ] {
        // Retained durably: the record names the gap; it certifies nothing. Since fss-f8jls
        // review D2 the policy never rejects over a gapped record (see
        // `the_policy_holds_a_gapped_record_indeterminate`), so the rejection the readers must
        // refuse here is written by the caller, citing every delivered frame's analysis.
        let mut quiet = Quiet::run_plan(
            tag,
            Plan {
                decide: forged,
                ..Plan::new(delivery, true)
            },
        )?;
        assert_eq!(quiet.decision.event.state, EventState::Rejected, "{tag}");
        let (batches, head) = quiet.history()?;
        assert_eq!(
            verify_retained_coverage(
                &quiet.record,
                Some(&quiet.decision.event),
                &quiet.analyses,
                &batches,
                &head
            ),
            Err(RetainedCoverageRefusal::WitnessDoesNotCertify),
            "{tag}"
        );
        assert_not_certified(&mut quiet, "not complete and continuous")?;
        quiet.cleanup();
    }
    Ok(())
}

#[test]
fn a_coverage_witness_delta_committed_without_source_custody_does_not_certify() -> TestResult {
    // The exact record and witness reach the ledger through the generic batch writer rather than
    // the producer's retention: the delta matches the record, but its batch holds custody of the
    // record and witness only, never of the source capsules and payloads.
    let mut quiet = Quiet::run("no-custody", everything, false)?;
    let record = quiet.record.clone();
    let cx = test_cx("no-custody-append")?;
    let deployment = quiet.deployment()?;
    let witness_object = deployment.stage_payload(&record.witness.canonical_bytes())?;
    let digest = deployment.stage_payload(&record.to_bytes())?;
    assert_eq!(witness_object, record.witness_object());
    assert_eq!(digest, record.digest());
    deployment.append_batch(
        BatchId::parse("batch:coverage:bypass")?,
        vec![EvidenceDelta {
            delta_id: "delta:coverage:bypass".to_owned(),
            family: FAMILY_COVERAGE_WITNESS.to_owned(),
            object_id: record.object_id()?,
            prior_generation: None,
            new_generation: 1,
            validity: record.interval,
            plane: Plane::Authority,
            payload_digest: digest,
            witness_digest: Some(witness_object),
            operation_id: None,
        }],
        vec![witness_object, digest],
        &cx,
    )?;
    commit_slot(
        quiet.deployment()?,
        "slot-bypass",
        vec![witness_object, digest],
        &cx,
    )?;
    let (batches, head) = quiet.history()?;
    // Every other condition holds: only custody is missing.
    assert!(record.source_objects().count() > 0);
    assert!(record.witness.certifies_absence());
    assert_eq!(
        verify_retained_coverage(
            &record,
            Some(&quiet.decision.event),
            &quiet.analyses,
            &batches,
            &head
        ),
        Err(RetainedCoverageRefusal::NoCustody)
    );
    assert_eq!(
        verify_retained_coverage(&record, None, &[], &batches, &head),
        Err(RetainedCoverageRefusal::NoCustody)
    );
    assert_not_certified(&mut quiet, "does not hold custody of every source object")?;
    quiet.cleanup();
    Ok(())
}

/// Unrelated history before the witness interval: a yard camera's capsule at [-10, -9] s,
/// committed and made reachable by a slot commit over that interval only.
fn yard_history(deployment: &mut ReferenceDeployment, cx: &ReplayCx) -> Result<(), Box<dyn Error>> {
    let yard = CaptureInterval::new(TimestampNs(-10_000_000_000), TimestampNs(-9_000_000_000))?;
    let packet = b"packet:cam-yard:-10";
    let payload = deployment.stage_payload(packet)?;
    let capsule = SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
        capsule_id: CapsuleId::parse("capsule:cam-yard:0")?,
        sensor_id: SensorId::parse("sensor:cam-yard")?,
        stream_id: StreamId::parse("stream:cam-yard")?,
        sequence: 0,
        capture: yard,
        receive_time: yard.latest,
        clock_basis: ClockBasis::DeviceMonotonic,
        source: packet,
        frame_count: 1,
        gap_before: false,
    })?;
    let digest = deployment.stage_payload(&capsule.canonical_bytes())?;
    let mut capsule_delta = delta(FAMILY_SENSOR_CAPSULE, "capsule:yard", digest)?;
    capsule_delta.validity = yard;
    deployment.append_batch(
        BatchId::parse("batch:yard-capsule")?,
        vec![capsule_delta],
        vec![payload, digest],
        cx,
    )?;
    let manifest = ObjectManifest::new("slot-yard", vec![payload, digest], None)?;
    deployment.publish_and_commit(&SlotName::parse("slot-yard")?, &manifest, yard, cx)?;
    Ok(())
}

#[test]
fn a_witness_based_after_unrelated_earlier_history_is_certified() -> TestResult {
    let mut quiet = Quiet::run_after("later-basis", everything, true, yard_history)?;
    // Basis commit 2 (after the yard capsule and its slot commit); after it: the event
    // publication (3), the record retention (4) and the run's slot commit (5).
    assert_eq!(quiet.record.witness.anchor.commit_sequence, 2);
    let (batches, head) = quiet.history()?;
    assert_eq!(head.commit_sequence, 5);
    // The pre-basis history is real, not bookkeeping of this witness, and outside its interval.
    let interval = quiet.record.interval;
    let pre_basis: Vec<&EvidenceDeltaBatch> = batches
        .iter()
        .filter(|batch| batch.new_anchor.commit_sequence <= 2)
        .collect();
    assert_eq!(pre_basis.len(), 2);
    for batch in &pre_basis {
        assert!(!batch.children.is_empty());
        assert!(batch.deltas.iter().all(|delta| {
            delta.validity.latest < interval.earliest || delta.validity.earliest > interval.latest
        }));
    }
    let absence = verify_retained_coverage(
        &quiet.record,
        Some(&quiet.decision.event),
        &quiet.analyses,
        &batches,
        &head,
    )
    .map_err(|refusal| format!("a later basis must certify: {refusal}"))?;
    assert_eq!(absence.basis_sequence, 2);
    assert_eq!(absence.record_sequence, 4);
    assert_eq!(absence.record_digest, quiet.record.digest());
    assert_certified(&mut quiet)?;
    quiet.cleanup();
    Ok(())
}

// --- the rule over kinds without a generic writer ---------------------------------------------

/// The real certified history extended by one synthetic batch (`edit` shapes it).
fn extended(
    quiet: &mut Quiet,
    edit: impl Fn(&mut EvidenceDeltaBatch) -> Result<(), Box<dyn Error>>,
) -> Result<Result<(), RetainedCoverageRefusal>, Box<dyn Error>> {
    let (real, real_head) = quiet.history()?;
    let mut batches = real.clone();
    let last = batches.last().ok_or("no batch")?.clone();
    let mut next = last.clone();
    next.batch_id = BatchId::parse("batch:synthetic")?;
    next.basis_anchor = last.new_anchor.clone();
    next.new_anchor.commit_sequence += 1;
    next.deltas = Vec::new();
    next.children = Vec::new();
    edit(&mut next)?;
    let head: LedgerAnchor = next.new_anchor.clone();
    batches.push(next);
    // Without the synthetic batch the rule certifies; with it, the verdict below.
    assert!(
        verify_retained_coverage(
            &quiet.record,
            Some(&quiet.decision.event),
            &quiet.analyses,
            &real,
            &real_head
        )
        .is_ok()
    );
    Ok(verify_retained_coverage(
        &quiet.record,
        Some(&quiet.decision.event),
        &quiet.analyses,
        &batches,
        &head,
    )
    .map(|_| ()))
}

#[test]
fn an_epoch_or_lineage_change_after_the_basis_invalidates() -> TestResult {
    let mut quiet = Quiet::run("epochs", everything, true)?;
    type Edit = fn(&mut LedgerAnchor);
    let edits: [(&str, Edit); 5] = [
        ("policy", |anchor| anchor.policy_epoch += 1),
        ("privacy", |anchor| anchor.privacy_epoch += 1),
        ("schema", |anchor| anchor.schema_epoch += 1),
        ("adapter registry", |anchor| {
            anchor.adapter_registry_epoch += 1
        }),
        ("ledger", |anchor| anchor.ledger_epoch += 1),
    ];
    for (name, edit) in edits {
        let verdict = extended(&mut quiet, |batch| {
            edit(&mut batch.new_anchor);
            Ok(())
        })?;
        assert!(
            matches!(
                verdict,
                Err(RetainedCoverageRefusal::EpochChanged { sequence: 4 })
                    | Err(RetainedCoverageRefusal::GenerationMismatch)
                    | Err(RetainedCoverageRefusal::BasisNotCommitted)
            ),
            "{name}: {verdict:?}"
        );
        assert!(verdict.is_err(), "{name}");
    }
    // An epoch the witness generation does not name is refused at the commit that changed it.
    let verdict = extended(&mut quiet, |batch| {
        batch.new_anchor.privacy_epoch += 1;
        Ok(())
    })?;
    assert_eq!(
        verdict,
        Err(RetainedCoverageRefusal::EpochChanged { sequence: 4 })
    );
    quiet.cleanup();
    Ok(())
}

#[test]
fn deletion_retention_and_hold_commits_after_the_basis_invalidate() -> TestResult {
    let mut quiet = Quiet::run("deletion", everything, true)?;
    let source = quiet
        .record
        .frames
        .first()
        .ok_or("no frame")?
        .capsule_digest;
    for family in [
        "deletion_record",
        "deletion_tombstone",
        "deletion_completion",
        "local_root_retraction",
        "evidence_hold",
        "alert_effect_outcome",
        "model_invocation_receipt",
        "executor_model_result",
        "file_import_manifest",
        "an_unregistered_family",
    ] {
        let verdict = extended(&mut quiet, |batch| {
            batch.deltas = vec![delta(family, "synthetic", source)?];
            Ok(())
        })?;
        assert!(
            matches!(
                &verdict,
                Err(RetainedCoverageRefusal::CoverageRelevantCommit { sequence: 4, family: named, .. })
                    if named == family
            ),
            "{family}: {verdict:?}"
        );
    }
    quiet.cleanup();
    Ok(())
}

#[test]
fn the_rule_refuses_events_it_does_not_certify() -> TestResult {
    let mut quiet = Quiet::run("event-shape", everything, true)?;
    let (batches, head) = quiet.history()?;
    let base = quiet.decision.event.clone();
    let verdict = |event: &EventHypothesis| {
        verify_retained_coverage(&quiet.record, Some(event), &quiet.analyses, &batches, &head)
    };
    assert!(verdict(&base).is_ok());

    let mut witnessed = base.clone();
    witnessed.state = EventState::Witnessed;
    assert_eq!(
        verdict(&witnessed),
        Err(RetainedCoverageRefusal::EventNotRejected)
    );

    let mut uncited = base.clone();
    for edge in &mut uncited.evidence {
        edge.digest = ContentDigest::sha256(b"some other evidence");
    }
    assert_eq!(
        verdict(&uncited),
        Err(RetainedCoverageRefusal::WitnessNotCited)
    );

    let mut breach = base.clone();
    breach.kind = EventKind::PerimeterBreach;
    assert_eq!(
        verdict(&breach),
        Err(RetainedCoverageRefusal::PredicateMismatch)
    );

    let mut zone = base.clone();
    zone.zone_ids = vec!["zone:garage".to_owned()];
    assert_eq!(
        verdict(&zone),
        Err(RetainedCoverageRefusal::DomainNotCovered)
    );

    let mut later = base.clone();
    later.interval = CaptureInterval::new(seconds(1)?, seconds(TICKS + 1)?)?;
    assert_eq!(
        verdict(&later),
        Err(RetainedCoverageRefusal::IntervalNotCovered)
    );

    // Without an event, the event publication after the basis is coverage-relevant.
    assert!(matches!(
        verify_retained_coverage(&quiet.record, None, &quiet.analyses, &batches, &head),
        Err(RetainedCoverageRefusal::CoverageRelevantCommit { sequence: 1, .. })
    ));
    quiet.cleanup();
    Ok(())
}

// --- analysis (fss-f8jls) -------------------------------------------------------------------------

/// The certifying run: the policy rejected over one analysis per frame, all under one generation,
/// and the certification names that generation.
#[test]
fn quiet_certifies_only_with_an_analysis_of_every_frame_under_one_generation() -> TestResult {
    let mut quiet = Quiet::run("analysed", everything, true)?;
    let event = &quiet.decision.event;
    assert_eq!(event.state, EventState::Rejected);
    assert_eq!(event.uncertainty_reason, None);
    assert_eq!(event.interval, quiet.record.interval);
    assert_eq!(event.model_receipts.len(), quiet.record.frames.len());
    // Every frame's capsule is cited, as contradicting evidence, under its own domain.
    for frame in &quiet.record.frames {
        assert!(
            event.evidence.iter().any(|edge| {
                edge.capsule_digest == Some(frame.capsule_digest)
                    && edge.failure_domain == frame.failure_domain
                    && edge.counts_as_contradiction()
            }),
            "frame {} is not cited",
            frame.capsule_digest
        );
    }
    let (batches, head) = quiet.history()?;
    let absence = verify_retained_coverage(
        &quiet.record,
        Some(&quiet.decision.event),
        &quiet.analyses,
        &batches,
        &head,
    )
    .map_err(|refusal| refusal.to_string())?;
    let analysis = absence.analysis.as_ref().ok_or("no analysis")?;
    assert_eq!(analysis.generation_id, GEN_A);
    assert_eq!(analysis.results.len(), quiet.record.frames.len());
    let statement = absence.statement();
    assert!(statement.contains(GEN_A), "{statement}");
    assert!(
        statement.contains("analysed all 10 of its frames"),
        "{statement}"
    );
    // The same event offered without its hydrated analyses is refused: the readers never take the
    // rejection's word for it.
    assert!(matches!(
        verify_retained_coverage(
            &quiet.record,
            Some(&quiet.decision.event),
            &[],
            &batches,
            &head
        ),
        Err(RetainedCoverageRefusal::AnalysisUnverified { .. })
    ));
    assert_certified(&mut quiet)?;
    quiet.cleanup();
    Ok(())
}

/// The pre-fss-f8jls lab: every frame delivered, the rejection written by the caller citing the
/// witness and no analysis. Delivery is not observation: neither reader certifies.
#[test]
fn a_rejection_written_without_analysis_does_not_certify() -> TestResult {
    // Exactly the old lab: nothing reaches a model, and the caller writes the rejection.
    let mut quiet = Quiet::run_plan(
        "lab-written",
        Plan {
            analyse: |_, _| None,
            decide: lab_written,
            ..Plan::new(everything, true)
        },
    )?;
    assert!(quiet.analyses.is_empty());
    assert!(quiet.decision.event.model_receipts.is_empty());
    let (batches, head) = quiet.history()?;
    assert_eq!(
        verify_retained_coverage(
            &quiet.record,
            Some(&quiet.decision.event),
            &quiet.analyses,
            &batches,
            &head
        ),
        Err(RetainedCoverageRefusal::NoAnalysis)
    );
    // Results the event does not cite add nothing, even when they cover every frame exactly.
    let spec = MockModelSpec::new(GEN_A, MockModelScript::NothingFound)?;
    let offered: Vec<MockModelResult> = quiet
        .record
        .frames
        .iter()
        .map(|frame| -> Result<MockModelResult, Box<dyn Error>> {
            Ok(MockModelResult {
                generation_id: GEN_A.to_owned(),
                sensor_id: SensorId::parse(frame.sensor_id.clone())?,
                model_spec_digest: spec.spec_digest(),
                input_capture_root: frame.source_digest,
                continuity_digest: frame.capsule_digest,
                outcome: crate::MockModelOutcome::NothingFound {
                    analysed_capsule: frame.capsule_digest,
                },
            })
        })
        .collect::<Result<_, _>>()?;
    assert_eq!(
        verify_retained_coverage(
            &quiet.record,
            Some(&quiet.decision.event),
            &offered,
            &batches,
            &head
        ),
        Err(RetainedCoverageRefusal::NoAnalysis)
    );
    assert_not_certified(&mut quiet, "delivered but never analysed")?;
    quiet.cleanup();
    Ok(())
}

fn all_but_one_frame(sensor: &str, tick: u64) -> Option<&'static str> {
    (!(sensor == SIDE.0 && tick == 3)).then_some(GEN_A)
}

fn one_frame_under_b(sensor: &str, tick: u64) -> Option<&'static str> {
    Some(if sensor == SIDE.0 && tick == 3 {
        GEN_B
    } else {
        GEN_A
    })
}

/// The unanalysed frame of [`all_but_one_frame`] / the other-generation frame of
/// [`one_frame_under_b`].
fn side_tick_3(quiet: &Quiet) -> Result<ContentDigest, Box<dyn Error>> {
    Ok(quiet
        .record
        .frames
        .iter()
        .find(|frame| frame.sensor_id == format!("sensor:{}", SIDE.0) && frame.sequence == 3)
        .ok_or("no side frame at tick 3")?
        .capsule_digest)
}

/// Analyses of only some frames: the policy holds the candidate indeterminate, and a forged
/// rejection citing those analyses is refused by both readers, naming the unanalysed frame.
#[test]
fn an_analysis_of_only_some_frames_does_not_certify() -> TestResult {
    let mut quiet = Quiet::run_plan(
        "partial-policy",
        Plan {
            analyse: all_but_one_frame,
            ..Plan::new(everything, true)
        },
    )?;
    let event = &quiet.decision.event;
    assert_eq!(event.state, EventState::Indeterminate);
    assert_eq!(
        event.uncertainty_reason.as_deref(),
        Some(COVERAGE_ANALYSIS_INCOMPLETE)
    );
    assert!(
        !event
            .evidence
            .iter()
            .any(|edge| edge.digest == quiet.record.witness_object())
    );
    // The compiler refuses to be offered a witness for an event that is not rejected; without
    // one, it states no absence certification at all.
    assert!(matches!(
        quiet.situation(true),
        Err(error) if error.to_string().contains("situation_coverage_witness_for_non_rejected_event")
    ));
    let situation = quiet.situation_without_coverage()?;
    let (cell, _, _) = situation_absence(&situation, &quiet.event_id);
    assert_ne!(cell, Some(KnowledgeState::Known));
    let durable = quiet.durable()?;
    assert!(!durable.certified(), "{durable:?}");
    assert!(durable.retained.is_none());
    quiet.cleanup();

    let mut quiet = Quiet::run_plan(
        "partial-forged",
        Plan {
            analyse: all_but_one_frame,
            decide: forged,
            ..Plan::new(everything, true)
        },
    )?;
    assert_eq!(quiet.decision.event.state, EventState::Rejected);
    assert_eq!(quiet.decision.event.model_receipts.len(), 9);
    let missing = side_tick_3(&quiet)?;
    let (batches, head) = quiet.history()?;
    assert_eq!(
        verify_retained_coverage(
            &quiet.record,
            Some(&quiet.decision.event),
            &quiet.analyses,
            &batches,
            &head
        ),
        Err(RetainedCoverageRefusal::AnalysisMissing { capsule: missing })
    );
    assert_not_certified(&mut quiet, "has no cited analysed-nothing model result")?;
    quiet.cleanup();
    Ok(())
}

/// Analyses under two generations: the policy does not mix them, and a forged rejection citing
/// both is refused by both readers.
#[test]
fn analyses_under_another_generation_do_not_certify() -> TestResult {
    let mut quiet = Quiet::run_plan(
        "generation-policy",
        Plan {
            analyse: one_frame_under_b,
            ..Plan::new(everything, true)
        },
    )?;
    assert_eq!(quiet.decision.event.state, EventState::Indeterminate);
    assert_eq!(
        quiet.decision.event.uncertainty_reason.as_deref(),
        Some(COVERAGE_ANALYSIS_INCOMPLETE)
    );
    let durable = quiet.durable()?;
    assert!(!durable.certified(), "{durable:?}");
    quiet.cleanup();

    let mut quiet = Quiet::run_plan(
        "generation-forged",
        Plan {
            analyse: one_frame_under_b,
            decide: forged,
            ..Plan::new(everything, true)
        },
    )?;
    assert_eq!(quiet.decision.event.state, EventState::Rejected);
    // Every frame is analysed and cited; one analysis is under the other generation.
    assert_eq!(
        quiet.decision.event.model_receipts.len(),
        quiet.record.frames.len()
    );
    let other = side_tick_3(&quiet)?;
    assert!(
        quiet
            .analyses
            .iter()
            .any(|result| { result.continuity_digest == other && result.generation_id == GEN_B })
    );
    let (batches, head) = quiet.history()?;
    assert_eq!(
        verify_retained_coverage(
            &quiet.record,
            Some(&quiet.decision.event),
            &quiet.analyses,
            &batches,
            &head
        ),
        Err(RetainedCoverageRefusal::AnalysisGenerationMixed)
    );
    assert_not_certified(&mut quiet, "span more than one model generation")?;
    quiet.cleanup();
    Ok(())
}

/// An analysis cited under another frame's capsule, domain or sensor does not cover that frame.
#[test]
fn an_analysis_bound_to_another_frame_does_not_count() -> TestResult {
    let mut quiet = Quiet::run("rebound", everything, true)?;
    let (batches, head) = quiet.history()?;
    let base = quiet.decision.event.clone();
    let verdict = |event: &EventHypothesis| {
        verify_retained_coverage(&quiet.record, Some(event), &quiet.analyses, &batches, &head)
    };
    assert!(verdict(&base).is_ok());

    // The edge names another capsule than the one the result analysed.
    let mut other_capsule = base.clone();
    if let Some(edge) = other_capsule
        .evidence
        .iter_mut()
        .find(|edge| edge.capsule_digest.is_some())
    {
        edge.capsule_digest = Some(ContentDigest::sha256(b"another capsule"));
    }
    assert!(matches!(
        verdict(&other_capsule),
        Err(RetainedCoverageRefusal::AnalysisUnverified { .. })
    ));

    // The edge cites a front frame's analysis under the side domain.
    let mut other_domain = base.clone();
    if let Some(edge) = other_domain
        .evidence
        .iter_mut()
        .find(|edge| edge.capsule_digest.is_some() && edge.failure_domain == FRONT.1)
    {
        edge.failure_domain = SIDE.1.to_owned();
    }
    assert!(matches!(
        verdict(&other_domain),
        Err(RetainedCoverageRefusal::AnalysisUnverified { .. })
    ));

    // A receipt the readers cannot hydrate as an analysed-nothing result.
    let mut unknown_receipt = base.clone();
    unknown_receipt
        .model_receipts
        .push(ContentDigest::sha256(b"an unretained result"));
    assert!(matches!(
        verdict(&unknown_receipt),
        Err(RetainedCoverageRefusal::AnalysisUnverified { .. })
    ));

    // One frame's analysis dropped from the event: that frame is unanalysed.
    let mut dropped = base.clone();
    let first = *dropped.model_receipts.first().ok_or("no receipt")?;
    dropped.model_receipts.retain(|receipt| *receipt != first);
    dropped.evidence.retain(|edge| edge.digest != first);
    let capsule = quiet
        .analyses
        .iter()
        .find(|result| result.object_digest() == first)
        .ok_or("no analysis")?
        .continuity_digest;
    assert_eq!(
        verdict(&dropped),
        Err(RetainedCoverageRefusal::AnalysisMissing { capsule })
    );
    quiet.cleanup();
    Ok(())
}

/// Over a coverage record, any finding is decided as the plain policy decides it; and without a
/// record an analysed-nothing result is a neutral edge that never rejects.
#[test]
fn analysed_nothing_rejects_only_over_a_covering_record() -> TestResult {
    let quiet = Quiet::run("policy-shape", everything, false)?;
    let observations = |results: &[MockModelResult]| -> Result<Vec<_>, Box<dyn Error>> {
        results
            .iter()
            .map(|result| {
                let frame = quiet
                    .record
                    .frames
                    .iter()
                    .find(|frame| frame.capsule_digest == result.continuity_digest)
                    .ok_or("no frame")?;
                Ok(ReferenceModelObservation::new(
                    result.clone(),
                    frame.failure_domain.clone(),
                    frame.capture,
                )?)
            })
            .collect()
    };
    let event_id = EventId::parse("event:source-coverage:policy-shape")?;

    // Without a record: every frame analysed with nothing found is indeterminate, never rejected.
    let plain = crate::evaluate_unknown_presence(event_id.clone(), observations(&quiet.analyses)?)?;
    assert_eq!(plain.event.state, EventState::Indeterminate);
    assert!(
        plain
            .event
            .evidence
            .iter()
            .all(|edge| edge.relation == EvidenceEdgeRelation::DerivedFrom
                && edge.capsule_digest.is_some())
    );

    // A person-like finding on one frame decides as the plain policy decides it.
    let person = MockModelSpec::new(
        "mock:model:person:v1",
        MockModelScript::Fixed {
            label: crate::MockSemanticLabel::PersonLike,
            probability: ProbabilityInterval::new(0.9, 1.0)?,
        },
    )?;
    let mut results = quiet.analyses.clone();
    let first = results.first().ok_or("no analysis")?.clone();
    let frame = quiet
        .record
        .frames
        .iter()
        .find(|frame| frame.capsule_digest == first.continuity_digest)
        .ok_or("no frame")?;
    let packet = format!(
        "packet:{}:{}",
        frame.sensor_id.trim_start_matches("sensor:"),
        frame.sequence
    );
    let capsule = SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
        capsule_id: CapsuleId::parse(format!(
            "capsule:{}:{}",
            frame.sensor_id.trim_start_matches("sensor:"),
            frame.sequence
        ))?,
        sensor_id: SensorId::parse(frame.sensor_id.clone())?,
        stream_id: StreamId::parse(frame.stream_id.clone())?,
        sequence: frame.sequence,
        capture: frame.capture,
        receive_time: frame.capture.latest,
        clock_basis: frame.clock_basis,
        source: packet.as_bytes(),
        frame_count: 1,
        gap_before: false,
    })?;
    assert!(frame_matches(frame, &capsule));
    results[0] = analyse_mock_capsule(&person, &capsule);
    let observed = observations(&results)?;
    let over =
        evaluate_unknown_presence_over_coverage(event_id.clone(), observed.clone(), &quiet.record)?;
    let plain = crate::evaluate_unknown_presence(event_id, observed)?;
    assert_eq!(over, plain);
    assert_ne!(over.event.state, EventState::Rejected);
    quiet.cleanup();
    Ok(())
}

fn frame_matches(frame: &super::SourceFrame, capsule: &SensorCapsule) -> bool {
    frame.matches(capsule)
}

// --- review r17 of fss-f8jls ----------------------------------------------------------------------

/// Observations of `results`, each under its frame's failure domain and capture interval.
fn observations_of(
    record: &SourceCoverageRecord,
    results: &[MockModelResult],
) -> Result<Vec<ReferenceModelObservation>, Box<dyn Error>> {
    results
        .iter()
        .map(|result| {
            let crate::MockModelOutcome::NothingFound { analysed_capsule } = result.outcome else {
                return Err("not an analysed-nothing result".into());
            };
            let frame = record
                .frames
                .iter()
                .find(|frame| frame.capsule_digest == analysed_capsule)
                .ok_or("no frame")?;
            Ok(ReferenceModelObservation::new(
                result.clone(),
                frame.failure_domain.clone(),
                frame.capture,
            )?)
        })
        .collect()
}

/// The policy's rejection plus one extra evidence edge it never produced: the receipts still
/// cover every frame, so only a rule that checks the whole decision refuses it.
fn with_extra_edge(decision: &mut ReferencePolicyDecision, edge: EventEvidence) -> TestResult {
    decision.event.evidence.push(edge);
    decision.event.decision_path = policy_decision_path(
        &decision.event.event_id,
        &decision.event.evidence,
        EventState::Rejected,
        ReferencePolicyAction::Hold,
    );
    decision.event.validate()?;
    Ok(())
}

/// A person-like result the event does not list as a model receipt, cited as support.
fn supporting_edge() -> EventEvidence {
    EventEvidence {
        digest: ContentDigest::sha256(b"r17 person-like result not listed as a receipt"),
        class: EvidenceClass::Derived,
        failure_domain: FRONT.1.to_owned(),
        supports: true,
        relation: EvidenceEdgeRelation::Supports,
        capsule_digest: None,
        identity_digest: None,
    }
}

/// Reviewer r17's probe (local commit 72f3d0f): the policy's rejection plus a forged supporting
/// edge. Before the fix both readers certified it.
fn policy_plus_support(
    event_id: &EventId,
    record: &SourceCoverageRecord,
    observations: Vec<ReferenceModelObservation>,
) -> Result<ReferencePolicyDecision, Box<dyn Error>> {
    let mut decision = by_policy(event_id, record, observations)?;
    assert_eq!(decision.event.state, EventState::Rejected);
    with_extra_edge(&mut decision, supporting_edge())?;
    Ok(decision)
}

/// D1: a rejected event that also carries evidence for presence is not the policy's decision;
/// neither the situation compiler nor the durable orient reader certifies it.
#[test]
fn a_rejection_carrying_evidence_for_presence_does_not_certify() -> TestResult {
    let mut quiet = Quiet::run_plan(
        "r17-support",
        Plan {
            decide: policy_plus_support,
            ..Plan::new(everything, true)
        },
    )?;
    // The probe's event really does carry a supporting edge beside covering receipts.
    assert!(
        quiet
            .decision
            .event
            .evidence
            .iter()
            .any(|edge| edge.counts_as_support())
    );
    assert_eq!(
        quiet.decision.event.model_receipts.len(),
        quiet.record.frames.len()
    );
    let (batches, head) = quiet.history()?;
    assert_eq!(
        verify_retained_coverage(
            &quiet.record,
            Some(&quiet.decision.event),
            &quiet.analyses,
            &batches,
            &head,
        ),
        Err(RetainedCoverageRefusal::DecisionNotReproducible)
    );
    assert_not_certified(&mut quiet, "is not the policy's decision")?;
    quiet.cleanup();
    Ok(())
}

/// D1: every other departure from the policy's decision is refused by the shared rule: a tamper
/// report, a non-receipt model edge, a neutral edge, an edge reordered, an uncertainty reason,
/// a probability, or a decision path that does not fingerprint the edges.
#[test]
fn the_rule_refuses_any_decision_the_policy_did_not_make() -> TestResult {
    let mut quiet = Quiet::run("r17-shapes", everything, true)?;
    let (batches, head) = quiet.history()?;
    let base = quiet.decision.clone();
    let verdict = |event: &EventHypothesis| {
        verify_retained_coverage(&quiet.record, Some(event), &quiet.analyses, &batches, &head)
    };
    assert!(verdict(&base.event).is_ok());
    let refused = Err(RetainedCoverageRefusal::DecisionNotReproducible);

    let tamper = EventEvidence {
        digest: ContentDigest::sha256(b"r17 tamper-like result"),
        class: EvidenceClass::Derived,
        failure_domain: SIDE.1.to_owned(),
        supports: EvidenceEdgeRelation::SensorTamper.required_supports_flag(),
        relation: EvidenceEdgeRelation::SensorTamper,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"sensor:cam-side")),
    };
    let other_model = EventEvidence {
        digest: ContentDigest::sha256(b"r17 another model's result"),
        class: EvidenceClass::Derived,
        failure_domain: FRONT.1.to_owned(),
        supports: false,
        relation: EvidenceEdgeRelation::Contradicts,
        capsule_digest: None,
        identity_digest: None,
    };
    let neutral = EventEvidence {
        relation: EvidenceEdgeRelation::DerivedFrom,
        supports: EvidenceEdgeRelation::DerivedFrom.required_supports_flag(),
        ..other_model.clone()
    };
    for (name, edge) in [
        ("support", supporting_edge()),
        ("tamper", tamper),
        ("other-model", other_model),
        ("neutral", neutral),
    ] {
        let mut decision = base.clone();
        with_extra_edge(&mut decision, edge)?;
        assert_eq!(verdict(&decision.event), refused, "{name}");
    }

    // The same edges in another order, with a path that fingerprints that order.
    let mut reordered = base.clone();
    reordered.event.evidence.reverse();
    reordered.event.decision_path = policy_decision_path(
        &reordered.event.event_id,
        &reordered.event.evidence,
        EventState::Rejected,
        ReferencePolicyAction::Hold,
    );
    reordered.event.validate()?;
    assert_eq!(verdict(&reordered.event), refused);

    // The policy's edges under a path the policy did not compute.
    let mut path = base.event.clone();
    path.decision_path = policy_decision_path(
        &path.event_id,
        &[],
        EventState::Rejected,
        ReferencePolicyAction::Hold,
    );
    assert_eq!(verdict(&path), refused);

    let mut reason = base.event.clone();
    reason.uncertainty_reason = Some("operator says nobody was there".to_owned());
    assert_eq!(verdict(&reason), refused);

    let mut probability = base.event.clone();
    probability.probability = ProbabilityInterval::new(0.0, 0.1)?;
    assert_eq!(verdict(&probability), refused);

    // An authorized zone, a track, or a narrowed interval the policy did not decide
    // (fss-pgwsv N1): each passes every earlier check and only the re-run policy refuses it.
    for (name, departure) in DEPARTURES {
        let mut decision = base.clone();
        departure(&mut decision)?;
        assert_ne!(decision.event, base.event, "{name}");
        assert_eq!(verdict(&decision.event), refused, "{name}");
    }
    // A widened interval leaves the record's interval, which the rule refuses before it re-runs
    // the policy.
    let mut widened = base.event.clone();
    widened.interval = CaptureInterval::new(seconds(0)?, seconds(TICKS + 1)?)?;
    assert_eq!(
        verdict(&widened),
        Err(RetainedCoverageRefusal::IntervalNotCovered)
    );
    quiet.cleanup();
    Ok(())
}

/// A departure from the policy's decision on a field the evidence edges do not carry.
type Departure = fn(&mut ReferencePolicyDecision) -> TestResult;

/// The departures fss-pgwsv N1 pins: an authorized zone, a track, and the interval narrowed at
/// either end. The re-review's mutants that skip zone/track or interval in the reproduction, or
/// compare only state, edges, reason, probability and path, accept every one of them.
const DEPARTURES: [(&str, Departure); 4] = [
    ("zone", |decision| {
        decision.event.zone_ids.push(SIDE.1.to_owned());
        decision.event.validate()?;
        Ok(())
    }),
    ("track", |decision| {
        decision.event.track_ids.push("track:pgwsv".to_owned());
        decision.event.validate()?;
        Ok(())
    }),
    ("narrowed-start", |decision| {
        decision.event.interval = CaptureInterval::new(seconds(1)?, seconds(TICKS)?)?;
        decision.event.validate()?;
        Ok(())
    }),
    ("narrowed-end", |decision| {
        decision.event.interval = CaptureInterval::new(seconds(0)?, seconds(TICKS - 1)?)?;
        decision.event.validate()?;
        Ok(())
    }),
];

/// fss-pgwsv N1 through both readers: the policy's rejection committed with each departure is
/// refused by the situation compiler and by the durable `fss orient` reader.
#[test]
fn a_rejection_with_a_zone_track_or_interval_the_policy_did_not_decide_does_not_certify()
-> TestResult {
    fn departed<const INDEX: usize>(
        event_id: &EventId,
        record: &SourceCoverageRecord,
        observations: Vec<ReferenceModelObservation>,
    ) -> Result<ReferencePolicyDecision, Box<dyn Error>> {
        let mut decision = by_policy(event_id, record, observations)?;
        assert_eq!(decision.event.state, EventState::Rejected);
        (DEPARTURES[INDEX].1)(&mut decision)?;
        Ok(decision)
    }
    let decides: [Decide; 4] = [departed::<0>, departed::<1>, departed::<2>, departed::<3>];
    for ((name, _), decide) in DEPARTURES.into_iter().zip(decides) {
        let mut quiet = Quiet::run_plan(
            &format!("pgwsv-{name}"),
            Plan {
                decide,
                ..Plan::new(everything, true)
            },
        )?;
        let (batches, head) = quiet.history()?;
        assert_eq!(
            verify_retained_coverage(
                &quiet.record,
                Some(&quiet.decision.event),
                &quiet.analyses,
                &batches,
                &head,
            ),
            Err(RetainedCoverageRefusal::DecisionNotReproducible),
            "{name}"
        );
        assert_not_certified(&mut quiet, "is not the policy's decision")?;
        quiet.cleanup();
    }
    Ok(())
}

/// D2: over a gapped record (a camera dark for one tick or the whole interval) the policy holds
/// the candidate indeterminate with a typed reason, citing no witness, even though every
/// delivered frame was analysed with nothing found.
#[test]
fn the_policy_holds_a_gapped_record_indeterminate() -> TestResult {
    fn one_tick(sensor: &str, tick: u64) -> bool {
        !(sensor == SIDE.0 && tick == 2)
    }
    fn whole(sensor: &str, _: u64) -> bool {
        sensor != SIDE.0
    }
    for (tag, delivery) in [
        ("policy-gap-tick", one_tick as Delivery),
        ("policy-gap-camera", whole),
    ] {
        let mut quiet = Quiet::run(tag, delivery, true)?;
        assert!(!quiet.record.witness.certifies_absence(), "{tag}");
        // Every delivered frame was analysed and found nothing.
        assert_eq!(quiet.analyses.len(), quiet.record.frames.len(), "{tag}");
        let event = &quiet.decision.event;
        assert_eq!(event.state, EventState::Indeterminate, "{tag}");
        assert_eq!(
            event.uncertainty_reason.as_deref(),
            Some(crate::COVERAGE_WITNESS_NOT_CERTIFYING),
            "{tag}"
        );
        assert!(
            !event
                .evidence
                .iter()
                .any(|edge| edge.digest == quiet.record.witness_object()
                    || edge.counts_as_contradiction()),
            "{tag}"
        );
        // No absence is stated as known by either reader.
        let situation = quiet.situation_without_coverage()?;
        let (cell, _, _) = situation_absence(&situation, &quiet.event_id);
        assert_ne!(cell, Some(KnowledgeState::Known), "{tag}");
        // The situation states why the event is indeterminate and keeps the protected
        // presence-live world (fss-pgwsv N2). (The compiler refuses a coverage witness offered
        // for a non-rejected event, so the gapped witness is never offered here.)
        let frame = &situation.capsule.frame;
        let stated = frame
            .unknown
            .iter()
            .filter(|line| line.contains(crate::COVERAGE_WITNESS_NOT_CERTIFYING))
            .count();
        assert_eq!(stated, 1, "{tag}: {:?}", frame.unknown);
        let presence_live = format!("world:event:{}:presence-live", quiet.event_id.as_str());
        assert!(
            frame
                .world_envelope
                .alternatives
                .iter()
                .any(|world| world.protected && world.world_id == presence_live),
            "{tag}"
        );
        assert!(
            quiet
                .situation(true)
                .is_err_and(|error| format!("{error:?}").contains("non_rejected_event")),
            "{tag}"
        );
        let durable = quiet.durable()?;
        assert!(!durable.certified(), "{tag}: {durable:?}");
        assert!(durable.retained.is_none(), "{tag}");
        quiet.cleanup();
    }
    Ok(())
}

/// D3: a result whose sensor, source payload, capsule binding or spec digest disagrees with the
/// frame it names does not cover that frame: the shared check refuses it, the policy holds the
/// candidate indeterminate, and a rejection citing it is refused by the rule.
#[test]
fn results_with_forged_internal_bindings_do_not_cover_their_frame() -> TestResult {
    let mut quiet = Quiet::run("r17-forged-fields", everything, true)?;
    let (batches, head) = quiet.history()?;
    let event_id = EventId::parse("event:source-coverage:r17-forged-fields")?;
    let honest = quiet.analyses.clone();
    let target = honest
        .iter()
        .position(|result| result.sensor_id.as_str() == format!("sensor:{}", FRONT.0))
        .ok_or("no front analysis")?;
    let original = honest[target].clone();
    let other_frame = quiet
        .record
        .frames
        .iter()
        .find(|frame| frame.capsule_digest != original.continuity_digest)
        .ok_or("no other frame")?
        .clone();
    let other_spec = MockModelSpec::with_descriptor(
        GEN_A,
        MockModelScript::NothingFound,
        crate::ModelGenerationDescriptor::for_generation("a different descriptor"),
    )?
    .spec_digest();
    assert_ne!(other_spec, original.model_spec_digest);

    type Forge = fn(&mut MockModelResult, &super::SourceFrame, ContentDigest);
    let forgeries: [(&str, Forge, bool); 4] = [
        (
            "sensor",
            |result, _, _| {
                result.sensor_id = SensorId::parse(format!("sensor:{}", SIDE.0))
                    .unwrap_or_else(|_| result.sensor_id.clone());
            },
            false,
        ),
        (
            "input_capture_root",
            |result, other, _| result.input_capture_root = other.source_digest,
            false,
        ),
        (
            "continuity_digest",
            |result, other, _| result.continuity_digest = other.capsule_digest,
            false,
        ),
        (
            "model_spec_digest",
            |result, _, spec| result.model_spec_digest = spec,
            true,
        ),
    ];
    for (name, forge, mixes_generation) in forgeries {
        let mut results = honest.clone();
        forge(&mut results[target], &other_frame, other_spec);
        assert_ne!(results[target], original, "{name}");
        let forged_digest = results[target].object_digest();
        let expected = if mixes_generation {
            RetainedCoverageRefusal::AnalysisGenerationMixed
        } else {
            RetainedCoverageRefusal::AnalysisUnverified {
                receipt: forged_digest,
            }
        };

        // The shared check.
        let cited: Vec<(&str, &MockModelResult)> = results
            .iter()
            .map(|result| -> Result<_, Box<dyn Error>> {
                let frame = quiet
                    .record
                    .frames
                    .iter()
                    .find(|frame| match result.outcome {
                        crate::MockModelOutcome::NothingFound { analysed_capsule } => {
                            frame.capsule_digest == analysed_capsule
                        }
                        _ => false,
                    })
                    .ok_or("no frame")?;
                Ok((frame.failure_domain.as_str(), result))
            })
            .collect::<Result<_, _>>()?;
        assert_eq!(
            super::analysis_covering_frames(&quiet.record, &cited),
            Err(expected.clone()),
            "{name}"
        );

        // The policy does not reject over it.
        let observations = observations_of(&quiet.record, &results)?;
        let decision = evaluate_unknown_presence_over_coverage(
            event_id.clone(),
            observations.clone(),
            &quiet.record,
        )?;
        assert_eq!(decision.event.state, EventState::Indeterminate, "{name}");
        assert_eq!(
            decision.event.uncertainty_reason.as_deref(),
            Some(COVERAGE_ANALYSIS_INCOMPLETE),
            "{name}"
        );

        // A rejection written to cite it is refused by the rule, naming the forged result.
        let rejection = forged(&event_id, &quiet.record, observations)?;
        assert_eq!(
            verify_retained_coverage(
                &quiet.record,
                Some(&rejection.event),
                &results,
                &batches,
                &head,
            ),
            Err(expected),
            "{name}"
        );
    }
    quiet.cleanup();
    Ok(())
}
