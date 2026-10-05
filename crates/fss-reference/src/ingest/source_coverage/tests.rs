//! Tests of the source coverage producer and the stored-witness rule (fss-tch7u).
//!
//! Every integration test drives a real [`ReferenceDeployment`]: capsules of two virtual cameras
//! are staged, the producer derives the witness, a rejected event cites it, the record is retained
//! with its exact approval, and the slot commit makes the run reachable, exactly as `fss-lab quiet`
//! does. Certification is then read from the compiled situation and from the durable `fss orient`
//! reader, which must agree. Epoch and lineage changes and the reserved deletion families have no
//! generic writer, so those kinds are exercised against the shared rule over the real committed
//! history extended by one synthetic batch.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::{
    AgentView, BatchId, BudgetVector, CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis,
    Completeness, ContentDigest, ContextAuthority, ContractBasis, ContractBasisRegistryBytes,
    ContractError, CoverageContinuity, CoverageWitness, EventEvidence, EventHypothesis, EventId,
    EventKind, EventState, EvidenceClass, EvidenceDelta, EvidenceDeltaBatch, EvidenceEdgeRelation,
    KnowledgeState, LedgerAnchor, MissionId, ObjectId, OperationId, Plane, PrincipalId,
    ProbabilityInterval, RootAuthoritySpec, SensorCapsule, SensorId, SensorSourceBytesSpec,
    SessionId, StreamId, TimestampNs,
};
use fss_object::ObjectManifest;
use fss_publication::SlotName;

use super::{
    RetainedCoverageRefusal, SourceCoverageError, SourceCoverageInput, SourceCoverageRecord,
    SourceCoverageStatus, build_source_coverage, retain_source_coverage, verify_retained_coverage,
};
use crate::agent_orient::{
    CLAIM_COVERAGE, OrientLimits, OrientRequest, orient_deployment, read_deployment,
};
use crate::reference_deployment::{
    FAMILY_COVERAGE_WITNESS, FAMILY_PRIVACY_MASK_POLICY, FAMILY_SENSOR_CAPSULE,
};
use crate::{
    ADP_REPLAY_ROW_ID, ReferenceDeployment, ReferenceEventReceipt, ReferencePolicyAction,
    ReferencePolicyDecision, ReferenceSituation, ReferenceSituationRequest, ReplayCx,
    ReplayIoAuthority, policy_decision_path,
};

type TestResult = Result<(), Box<dyn Error>>;

const SITE: &str = "site:source-coverage";
const FRONT: (&str, &str) = ("cam-front", "front-power-and-network");
const SIDE: (&str, &str) = ("cam-side", "side-power-and-network");
const TICKS: u64 = 5;
const PREDICATE: &str = "no_unknown_person_present";

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

/// One `quiet` run on a real deployment, stopped after the slot commit.
struct Quiet {
    root: PathBuf,
    cx: ReplayCx,
    deployment: Option<ReferenceDeployment>,
    record: SourceCoverageRecord,
    decision: ReferencePolicyDecision,
    receipt: ReferenceEventReceipt,
    event_id: EventId,
}

impl Quiet {
    /// Runs the lab flow; `retain` false never retains the record (a stored but unretained
    /// witness).
    fn run(tag: &str, delivery: Delivery, retain: bool) -> Result<Self, Box<dyn Error>> {
        Self::run_after(tag, delivery, retain, |_, _| Ok(()))
    }

    /// [`Self::run`] after `prelude` commits earlier history: the witness basis is the anchor the
    /// prelude leaves.
    fn run_after(
        tag: &str,
        delivery: Delivery,
        retain: bool,
        prelude: Prelude,
    ) -> Result<Self, Box<dyn Error>> {
        let root = fresh_root(tag)?;
        let cx = test_cx(tag)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        prelude(&mut deployment, &cx)?;
        let mut staged = Vec::new();
        let mut sources = Vec::new();
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
        staged.push(witness_object);
        let event_id = EventId::parse(format!("event:source-coverage:{tag}"))?;
        let decision = rejected(&event_id, witness_object, &record.witness, 1, None)?;
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
        let decision = self.decision.clone();
        let receipt = self.receipt.clone();
        let cx = test_cx("compile")?;
        let request = ReferenceSituationRequest {
            mission_id: MissionId::parse("mission:source-coverage")?,
            session_id: SessionId::parse("session:source-coverage")?,
            principal_id: PrincipalId::parse("principal:source-coverage")?,
            objective_id: "objective:source-coverage".to_owned(),
            revision: 1,
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
            coverage_witness: Some(witness),
            coverage_record: record,
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

    let durable = quiet.durable()?;
    assert!(durable.certified(), "{durable:?}");
    assert_eq!(durable.retained, Some(record));
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
    // Revision 2 of the same event, still rejected and still citing the witness: the witness
    // basis now precedes two publications of the event, so revision 1's is not bookkeeping.
    let witness_object = quiet.record.witness_object();
    let decision = rejected(
        &quiet.event_id,
        witness_object,
        &quiet.record.witness,
        2,
        Some(quiet.decision.event.revision_digest()),
    )?;
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
        verify_retained_coverage(&copy, Some(&quiet.decision.event), &batches, &head),
        Err(RetainedCoverageRefusal::WitnessNotCited)
    );
    // Nor does the later basis hide what preceded it: the event publication at commit 1 bears on
    // the interval and is not the copy's bookkeeping.
    assert!(matches!(
        verify_retained_coverage(&copy, None, &batches, &head),
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
        verify_retained_coverage(&tampered, Some(&quiet.decision.event), &batches, &head),
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
        // Retained durably: the record names the gap; it certifies nothing.
        let mut quiet = Quiet::run(tag, delivery, true)?;
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
        verify_retained_coverage(&record, Some(&quiet.decision.event), &batches, &head),
        Err(RetainedCoverageRefusal::NoCustody)
    );
    assert_eq!(
        verify_retained_coverage(&record, None, &batches, &head),
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
    let absence =
        verify_retained_coverage(&quiet.record, Some(&quiet.decision.event), &batches, &head)
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
            &real,
            &real_head
        )
        .is_ok()
    );
    Ok(
        verify_retained_coverage(&quiet.record, Some(&quiet.decision.event), &batches, &head)
            .map(|_| ()),
    )
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
        verify_retained_coverage(&quiet.record, Some(event), &batches, &head)
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
        verify_retained_coverage(&quiet.record, None, &batches, &head),
        Err(RetainedCoverageRefusal::CoverageRelevantCommit { sequence: 1, .. })
    ));
    quiet.cleanup();
    Ok(())
}
