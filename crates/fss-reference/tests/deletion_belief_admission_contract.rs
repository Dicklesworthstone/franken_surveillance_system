#![forbid(unsafe_code)]
//! Native deletion-proof admission, including a durable header before any content is unlinked.
//! All fault injection changes only these tests' synthetic deployments.

mod file_import_fault_support;

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use file_import_fault_support::{TestResult, cx, fixture, fresh_dir, open, request, standard};
use fss_core::belief_verification::{BeliefRebuildInputs, RegisteredBeliefDeriver};
use fss_core::{
    BatchId, BeliefInterval, CanonicalEncode, CaptureInterval, ContentDigest, ContractError,
    DerivedBelief, DerivedBeliefParams, EvidenceDelta, Generation, KnowledgeState, ObjectId,
    Plane, ProvenanceClass, TimestampNs,
};
use fss_object::HostSpoolIo;
use fss_publication::SlotName;
use fss_publication::custody_audit::belief_snapshot::durable::{
    DurableBeliefDeletionAuthority, DurableBeliefError, DurableBeliefLimits, DurableBeliefRequest,
};
use fss_reference::deletion::belief::{
    BoundedCommittedDeletionBeliefAuthority, DeletionBeliefLimits, DeletionBeliefUsage,
    verify_durable_belief_with_committed_deletions,
};
use fss_reference::deletion::{
    DeletionError, DeletionIndex, DeletionPlan, STAGE_DELETION_AUTHORITY_BATCH_APPENDED,
    commit_deletion, plan_deletion,
};
use fss_reference::{DeploymentLimits, FileIngestAdapter, ReferenceDeployment};

type Value<T> = Result<T, Box<dyn std::error::Error>>;
const PRINCIPAL: &str = "operator:deletion-belief-admission";

struct Harness {
    deployment: ReferenceDeployment,
    root: PathBuf,
    limits: DeploymentLimits,
    plan: DeletionPlan,
    victim_slot: SlotName,
    victim_root: ContentDigest,
    survivor_slot: SlotName,
}

fn setup(label: &str, partial: bool) -> Value<Harness> {
    let dir = fresh_dir(&format!("deletion-belief-admission-{label}"))?;
    let root = dir.join("deployment");
    let limits = DeploymentLimits {
        batch_entries_max: 16,
        manifest_children_max: 8,
        ..standard()
    };
    let mut deployment = open(&root, limits)?;
    let context = cx("belief-admission-setup")?;
    let survivor_slot = SlotName::parse("admission-survivor")?;
    let staged = deployment.stage_and_publish(&survivor_slot, &[&[7_u8][..]], &context)?;
    deployment.publish_and_commit(
        &survivor_slot,
        &staged.manifest,
        CaptureInterval::new(TimestampNs(1), TimestampNs(2))?,
        &context,
    )?;
    let frame = fs::read(fixture("jpeg/gray_16x16_flat.jpg")?)?;
    let input = dir.join("input.mjpeg");
    fs::write(&input, frame.repeat(if partial { 40 } else { 2 }))?;
    let retained = FileIngestAdapter::ingest(
        request(&input, frame.len() as u64, 8)?,
        &context,
        &mut deployment,
    )?;
    let victim_root = retained.import_root;
    let victim_slot = deployment
        .publisher()
        .visible_roots()
        .find(|entry| entry.root == victim_root)
        .ok_or("missing victim publication")?
        .slot
        .clone();
    let plan = plan_deletion(&deployment, retained.import_identity, &context)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    let commit_context = cx("belief-admission-commit")?;
    if partial {
        assert!(plan.tombstones.len() > limits.batch_entries_max);
        commit_context.set_cancel_at_checkpoint_occurrence(
            STAGE_DELETION_AUTHORITY_BATCH_APPENDED,
            1,
        );
    }
    let result = commit_deletion(
        &mut deployment,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &commit_context,
    );
    if partial {
        assert!(matches!(result, Err(DeletionError::Cancelled { .. })));
        let last = deployment.ledger().batches().last().ok_or("no deletion header")?;
        assert_eq!(last.deltas.len(), 1);
        assert_eq!(last.deltas[0].family, "deletion_record");
    } else {
        let _ = result?;
    }
    Ok(Harness { deployment, root, limits, plan, victim_slot, victim_root, survivor_slot })
}

fn expected(h: &Harness) -> Value<BTreeMap<ContentDigest, ContentDigest>> {
    let proof = h.plan.digest()?;
    Ok(h.plan.deletable.iter().map(|object| (object.digest, proof)).collect())
}

fn record_sizes(h: &Harness) -> Value<Vec<usize>> {
    let index = DeletionIndex::read(&h.deployment)?;
    let entry = index.plan(h.plan.digest()?).ok_or("no plan")?;
    let mut sizes = vec![h.deployment.publisher().spool().read(entry.plan_digest)?.len()];
    if let Some(completion) = entry.completion_digest {
        sizes.push(h.deployment.publisher().spool().read(completion)?.len());
    }
    Ok(sizes)
}

fn tree(root: &Path) -> Value<BTreeMap<PathBuf, ContentDigest>> {
    let mut result = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else {
                result.insert(
                    entry.path().strip_prefix(root)?.to_path_buf(),
                    ContentDigest::sha256(&fs::read(entry.path())?),
                );
            }
        }
    }
    Ok(result)
}

#[test]
fn completed_proof_uses_only_exact_metadata_and_retains_nonrefillable_usage() -> TestResult {
    let h = setup("complete", false)?;
    let before = tree(&h.root)?;
    let owner = BoundedCommittedDeletionBeliefAuthority::new(DeletionBeliefLimits::default(), &|| false);
    let denials = owner.verified_denials(h.deployment.ledger(), h.deployment.publisher())?;
    assert_eq!(denials, expected(&h)?);
    let used = owner.usage();
    assert_eq!(used.history_batches, h.deployment.ledger().batches().len());
    assert_eq!(used.history_entries, h.deployment.ledger().batches().iter()
        .map(|batch| batch.deltas.len() + batch.children.len()).sum::<usize>());
    assert_eq!(used.record_reads, 2);
    assert_eq!(used.record_bytes, record_sizes(&h)?.iter().sum::<usize>());
    assert_eq!(used.denied_objects, denials.len());
    assert!(used.plan_entries >= denials.len());
    assert!(owner.attempted());
    assert!(matches!(owner.verified_denials(h.deployment.ledger(), h.deployment.publisher()),
        Err(DurableBeliefError::Limit("deletion admission attempts"))));
    assert_eq!(owner.usage(), used);
    assert_eq!(tree(&h.root)?, before);
    Ok(())
}

#[test]
fn every_allowance_refuses_one_below_required_and_exact_boundaries_succeed() -> TestResult {
    let h = setup("limits", false)?;
    let owner = BoundedCommittedDeletionBeliefAuthority::new(DeletionBeliefLimits::default(), &|| false);
    let denials = owner.verified_denials(h.deployment.ledger(), h.deployment.publisher())?;
    let used = owner.usage();
    let exact = DeletionBeliefLimits {
        max_history_batches: used.history_batches,
        max_history_entries: used.history_entries,
        max_record_reads: used.record_reads,
        max_record_bytes: *record_sizes(&h)?.iter().max().ok_or("no records")?,
        max_total_record_bytes: used.record_bytes,
        max_plan_entries: used.plan_entries,
        max_denied_objects: used.denied_objects,
    };
    let owner = BoundedCommittedDeletionBeliefAuthority::new(exact, &|| false);
    assert_eq!(owner.verified_denials(h.deployment.ledger(), h.deployment.publisher())?, denials);
    assert_eq!(owner.usage(), used);
    for (limits, reason) in [
        (DeletionBeliefLimits { max_history_batches: exact.max_history_batches - 1, ..exact }, "deletion history batches"),
        (DeletionBeliefLimits { max_history_entries: exact.max_history_entries - 1, ..exact }, "deletion history entries"),
        (DeletionBeliefLimits { max_record_reads: exact.max_record_reads - 1, ..exact }, "deletion record reads"),
        (DeletionBeliefLimits { max_plan_entries: exact.max_plan_entries - 1, ..exact }, "deletion plan entries"),
        (DeletionBeliefLimits { max_denied_objects: exact.max_denied_objects - 1, ..exact }, "deletion denied objects"),
    ] {
        let owner = BoundedCommittedDeletionBeliefAuthority::new(limits, &|| false);
        assert!(matches!(owner.verified_denials(h.deployment.ledger(), h.deployment.publisher()),
            Err(DurableBeliefError::Limit(actual)) if actual == reason));
        let consumed = owner.usage();
        assert!(consumed.record_bytes <= limits.max_total_record_bytes);
        assert!(consumed.plan_entries <= limits.max_plan_entries);
        assert!(consumed.denied_objects <= limits.max_denied_objects);
        assert!(owner.verified_denials(h.deployment.ledger(), h.deployment.publisher()).is_err());
        assert_eq!(owner.usage(), consumed);
    }
    // The native spool, not a post-read allocation check, enforces both byte ceilings.
    for limits in [
        DeletionBeliefLimits { max_record_bytes: exact.max_record_bytes - 1, ..exact },
        DeletionBeliefLimits { max_total_record_bytes: exact.max_total_record_bytes - 1, ..exact },
    ] {
        let owner = BoundedCommittedDeletionBeliefAuthority::new(limits, &|| false);
        assert!(owner.verified_denials(h.deployment.ledger(), h.deployment.publisher()).is_err());
        assert!(owner.usage().record_bytes <= limits.max_total_record_bytes);
    }
    Ok(())
}

#[test]
fn cancellation_at_every_checkpoint_returns_no_partial_denial_set() -> TestResult {
    let h = setup("cancellation", false)?;
    let count = AtomicUsize::new(0);
    let count_only = || { count.fetch_add(1, Ordering::Relaxed); false };
    let owner = BoundedCommittedDeletionBeliefAuthority::new(DeletionBeliefLimits::default(), &count_only);
    let _ = owner.verified_denials(h.deployment.ledger(), h.deployment.publisher())?;
    let checkpoints = count.load(Ordering::Relaxed);
    assert!(checkpoints > 5);
    let before = tree(&h.root)?;
    for at in 1..=checkpoints {
        let count = AtomicUsize::new(0);
        let cancelled = || count.fetch_add(1, Ordering::Relaxed) + 1 >= at;
        let owner = BoundedCommittedDeletionBeliefAuthority::new(DeletionBeliefLimits::default(), &cancelled);
        assert!(matches!(owner.verified_denials(h.deployment.ledger(), h.deployment.publisher()),
            Err(DurableBeliefError::Cancelled)), "checkpoint {at}");
        let used = owner.usage();
        assert!(owner.attempted());
        assert!(owner.verified_denials(h.deployment.ledger(), h.deployment.publisher()).is_err());
        assert_eq!(owner.usage(), used);
        if at == 1 { assert_eq!(used, DeletionBeliefUsage::default()); }
    }
    assert_eq!(tree(&h.root)?, before);
    Ok(())
}

#[test]
fn corrupt_record_keeps_its_read_reservation_and_is_never_repaired() -> TestResult {
    let h = setup("corrupt-plan", false)?;
    let path = h.deployment.publisher().spool().object_path(h.plan.digest()?);
    let mut bytes = fs::read(&path)?;
    *bytes.last_mut().ok_or("empty envelope")? ^= 0x80;
    fs::write(&path, &bytes)?;
    let limits = DeletionBeliefLimits { max_record_bytes: 64 * 1024, ..Default::default() };
    let owner = BoundedCommittedDeletionBeliefAuthority::new(limits, &|| false);
    assert!(matches!(owner.verified_denials(h.deployment.ledger(), h.deployment.publisher()),
        Err(DurableBeliefError::DeletionAuthorityInvalid)));
    let used = owner.usage();
    assert_eq!(used.record_reads, 1);
    assert_eq!(used.record_bytes, limits.max_record_bytes);
    assert_eq!(used.denied_objects, 0);
    assert!(owner.verified_denials(h.deployment.ledger(), h.deployment.publisher()).is_err());
    assert_eq!(owner.usage(), used);
    assert_eq!(fs::read(path)?, bytes);
    Ok(())
}

#[test]
fn unknown_deletion_family_refuses_before_any_metadata_read() -> TestResult {
    let mut h = setup("unknown-family", false)?;
    let proof = h.plan.digest()?;
    let _ = h.deployment.append_batch(BatchId::parse("batch:future-deletion-family")?, vec![EvidenceDelta {
        delta_id: "delta:future-deletion".to_owned(), family: "deletion_future".to_owned(),
        object_id: ObjectId::parse("object:future-deletion")?, prior_generation: None,
        new_generation: 1, validity: h.plan.validity, plane: Plane::Authority,
        payload_digest: proof, witness_digest: None, operation_id: None,
    }], vec![proof], &cx("belief-unknown-family")?)?;
    let owner = BoundedCommittedDeletionBeliefAuthority::new(DeletionBeliefLimits::default(), &|| false);
    assert!(matches!(owner.verified_denials(h.deployment.ledger(), h.deployment.publisher()),
        Err(DurableBeliefError::DeletionAuthorityInvalid)));
    assert_eq!(owner.usage().record_reads, 0);
    assert_eq!(owner.usage().record_bytes, 0);
    Ok(())
}

fn offered(anchor: &fss_core::LedgerAnchor, root: ContentDigest) -> Result<DerivedBelief, ContractError> {
    DerivedBelief::new(DerivedBeliefParams {
        belief_id: "belief:deletion-admission".to_owned(), anchor: anchor.clone(),
        generation: Generation(1), algorithm_id: "alg:deletion-admission:v1".to_owned(),
        statement: "the retained fixture byte is seven".to_owned(),
        knowledge_state: KnowledgeState::Estimated, provenance: ProvenanceClass::Derived,
        uncertainty: BeliefInterval::new(0, 1_000_000)?, supporting_evidence: vec![root],
        contradictions: vec![], derivation_receipt: ContentDigest::sha256(b"unsealed"),
    }.with_computed_receipt()?)
}

#[derive(Default)]
struct ByteEngine { calls: Cell<usize> }
impl RegisteredBeliefDeriver for ByteEngine {
    fn algorithm_id(&self) -> &str { "alg:deletion-admission:v1" }
    fn generation(&self) -> Generation { Generation(1) }
    fn derive(&self, input: &BeliefRebuildInputs<'_>) -> Result<DerivedBelief, ContractError> {
        self.calls.set(self.calls.get() + 1);
        let [evidence] = input.supporting else { return Err(ContractError::EvidenceRequired); };
        if evidence.bytes() != [7] || !input.contradicting.is_empty() || evidence.ancestry().is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        offered(input.anchor, evidence.digest())
    }
}

fn assert_pending_denial(h: &Harness) -> TestResult {
    let before = tree(&h.root)?;
    for object in &h.plan.deletable {
        assert!(h.deployment.publisher().object_name_present(object.digest));
    }
    let owner = BoundedCommittedDeletionBeliefAuthority::new(DeletionBeliefLimits::default(), &|| false);
    let denials = owner.verified_denials(h.deployment.ledger(), h.deployment.publisher())?;
    assert_eq!(denials, expected(h)?);
    assert!(denials.contains_key(&h.victim_root));
    assert_eq!(owner.usage().record_reads, 1);
    assert!(!DeletionIndex::read(&h.deployment)?.plan(h.plan.digest()?).ok_or("no header")?.is_complete());
    // The victim slot still has its original generation and all its bytes. The committed
    // plan now refuses its slot selection BEFORE native capture, not only when the capture
    // eventually encounters a denied root. This also covers roots retained under another slot.
    let victim = offered(h.deployment.current_anchor(), h.victim_root)?;
    let engine = ByteEngine::default();
    let denied = BTreeMap::new();
    assert!(matches!(verify_durable_belief_with_committed_deletions(
        &victim.canonical_bytes(), &h.deployment, &HostSpoolIo, &engine,
        DurableBeliefRequest { slots: &[h.victim_slot.clone()], denied: &denied,
            limits: DurableBeliefLimits::default(), cancelled: &|| false },
    ), Err(DurableBeliefError::Selection)));
    assert_eq!(engine.calls.get(), 0);
    let survivor = offered(h.deployment.current_anchor(), ContentDigest::sha256(&[7]))?;
    let verified = verify_durable_belief_with_committed_deletions(
        &survivor.canonical_bytes(), &h.deployment, &HostSpoolIo, &engine,
        DurableBeliefRequest { slots: &[h.survivor_slot.clone()], denied: &denied,
            limits: DurableBeliefLimits::default(), cancelled: &|| false },
    )?;
    assert_eq!(verified.belief(), &survivor);
    assert_eq!(engine.calls.get(), 1);
    assert!(!verified.to_knowledge_cell(&|| false)?.is_irreversible_effect_premise(TimestampNs(2)));
    assert_eq!(tree(&h.root)?, before);
    Ok(())
}

#[test]
fn a_header_only_deletion_denies_surviving_bytes_without_disabling_other_slots() -> TestResult {
    let h = setup("header", true)?;
    assert_pending_denial(&h)
}

#[test]
fn cold_reopen_preserves_header_denials_without_finishing_or_repairing_deletion() -> TestResult {
    let h = setup("cold-header", true)?;
    let Harness { deployment, root, limits, plan, victim_slot, victim_root, survivor_slot } = h;
    drop(deployment);
    let deployment = open(&root, limits)?;
    let h = Harness { deployment, root, limits, plan, victim_slot, victim_root, survivor_slot };
    assert_pending_denial(&h)
}

#[test]
fn selected_slot_proof_is_one_attempt_and_is_not_an_object_map_shortcut() -> TestResult {
    let h = setup("slot-admission", true)?;
    assert!(h.plan.retractions.iter().any(|r| r.slot == h.victim_slot.as_str()));
    let owner = BoundedCommittedDeletionBeliefAuthority::new(DeletionBeliefLimits::default(), &|| false);
    assert!(matches!(owner.verified_denials_for_slots(
        h.deployment.ledger(), h.deployment.publisher(), &[h.victim_slot.clone()]),
        Err(DurableBeliefError::Selection)));
    let used = owner.usage();
    assert_eq!(used.record_reads, 1);
    assert!(matches!(owner.verified_denials(h.deployment.ledger(), h.deployment.publisher()),
        Err(DurableBeliefError::Limit("deletion admission attempts"))));
    assert_eq!(owner.usage(), used);
    let owner = BoundedCommittedDeletionBeliefAuthority::new(DeletionBeliefLimits::default(), &|| false);
    assert_eq!(owner.verified_denials_for_slots(
        h.deployment.ledger(), h.deployment.publisher(), &[h.survivor_slot.clone()])?, expected(&h)?);
    Ok(())
}

#[test]
fn legacy_object_only_authority_cannot_claim_unchecked_slot_authority() -> TestResult {
    struct ObjectOnly;
    impl DurableBeliefDeletionAuthority for ObjectOnly {
        fn verified_denials(&self, _: &fss_ledger::DurableReferenceLedger, _: &fss_publication::LocalRootPublisher)
            -> Result<BTreeMap<ContentDigest, ContentDigest>, DurableBeliefError> { Ok(BTreeMap::new()) }
    }
    let h = setup("object-only", true)?;
    assert!(matches!(ObjectOnly.verified_denials_for_slots(
        h.deployment.ledger(), h.deployment.publisher(), &[h.victim_slot.clone()]),
        Err(DurableBeliefError::DeletionAuthorityInvalid)));
    let engine = ByteEngine::default();
    let belief = offered(h.deployment.current_anchor(), ContentDigest::sha256(&[7]))?;
    let denied = BTreeMap::new();
    assert!(matches!(fss_publication::custody_audit::belief_snapshot::durable::verify_durable_belief_with_deletion_authority(
        &belief.canonical_bytes(), h.deployment.ledger(), h.deployment.publisher(), &HostSpoolIo,
        &engine, &ObjectOnly, DurableBeliefRequest { slots: &[h.survivor_slot.clone()], denied: &denied,
            limits: DurableBeliefLimits::default(), cancelled: &|| false }),
        Err(DurableBeliefError::DeletionAuthorityInvalid)));
    assert_eq!(engine.calls.get(), 0);
    Ok(())
}

#[test]
fn duplicate_selected_slots_are_refused_before_deletion_metadata_reads() -> TestResult {
    let h = setup("duplicate-slot", true)?;
    let owner = BoundedCommittedDeletionBeliefAuthority::new(DeletionBeliefLimits::default(), &|| false);
    assert!(matches!(owner.verified_denials_for_slots(
        h.deployment.ledger(), h.deployment.publisher(), &[h.survivor_slot.clone(), h.survivor_slot.clone()]),
        Err(DurableBeliefError::Selection)));
    assert_eq!(owner.usage(), DeletionBeliefUsage::default());
    Ok(())
}
