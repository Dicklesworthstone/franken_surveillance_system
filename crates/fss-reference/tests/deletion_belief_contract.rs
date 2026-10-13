#![forbid(unsafe_code)]
//! Committed deletion authority narrows durable belief custody without globally disabling it.

mod file_import_fault_support;

use std::collections::BTreeMap;
use std::fs;

use file_import_fault_support::{cx, fixture, fresh_dir, open, request, standard, TestResult};
use fss_core::belief_verification::{
    BeliefRebuildInputs, RegisteredBeliefDeriver,
};
use fss_core::{
    BatchId, BeliefInterval, CanonicalEncode, CaptureInterval, ContentDigest, ContractError, DerivedBelief,
    DerivedBeliefParams, Generation, KnowledgeState, ProvenanceClass, TimestampNs,
};
use fss_object::HostSpoolIo;
use fss_publication::custody_audit::belief_snapshot::durable::{
    DurableBeliefDeletionAuthority, DurableBeliefError, DurableBeliefLimits, DurableBeliefRequest,
    verify_durable_belief,
};
use fss_publication::SlotName;
use fss_reference::deletion::belief::{
    CommittedDeletionBeliefAuthority, verify_durable_belief_with_committed_deletions,
};
use fss_reference::deletion::{commit_deletion, plan_deletion};
use fss_reference::{FileIngestAdapter, ReferenceDeployment};

const PRINCIPAL: &str = "operator:belief-deletion-contract";
const ALGORITHM: &str = "alg:deletion-survivor:v1";

struct ByteEngine;
impl RegisteredBeliefDeriver for ByteEngine {
    fn algorithm_id(&self) -> &str { ALGORITHM }
    fn generation(&self) -> Generation { Generation(1) }

    fn derive(&self, input: &BeliefRebuildInputs<'_>) -> Result<DerivedBelief, ContractError> {
        let [evidence] = input.supporting else {
            return Err(ContractError::EvidenceRequired);
        };
        if !input.contradicting.is_empty()
            || evidence.bytes() != [7]
            || evidence.ancestry().is_empty()
        {
            return Err(ContractError::EvidenceRequired);
        }
        make_belief(input.anchor, evidence.digest())
    }
}

fn make_belief(
    anchor: &fss_core::LedgerAnchor,
    evidence: ContentDigest,
) -> Result<DerivedBelief, ContractError> {
    DerivedBelief::new(
        DerivedBeliefParams {
            belief_id: "belief:deletion-survivor".to_owned(),
            anchor: anchor.clone(),
            generation: Generation(1),
            algorithm_id: ALGORITHM.to_owned(),
            statement: "retained byte seven is independently verified".to_owned(),
            knowledge_state: KnowledgeState::Estimated,
            provenance: ProvenanceClass::Derived,
            uncertainty: BeliefInterval::new(0, 1_000_000)?,
            supporting_evidence: vec![evidence],
            contradictions: vec![],
            derivation_receipt: ContentDigest::sha256(b"unsealed"),
        }
        .with_computed_receipt()?,
    )
}

struct Harness {
    deployment: ReferenceDeployment,
    selected: Vec<SlotName>,
    leaf: ContentDigest,
    import: ContentDigest,
    plan_digest: ContentDigest,
    deleted: Vec<ContentDigest>,
}

fn harness(label: &str) -> Result<Harness, Box<dyn std::error::Error>> {
    let dir = fresh_dir(label)?;
    let root = dir.join("deployment");
    let mut deployment = open(&root, standard())?;
    let context = cx(label)?;

    // Independent authority that must survive deletion of another retained closure.
    let slot = SlotName::parse("belief-survivor")?;
    let staged = deployment.stage_and_publish(&slot, &[&[7_u8][..]], &context)?;
    deployment.publish_and_commit(
        &slot,
        &staged.manifest,
        CaptureInterval::new(TimestampNs(1), TimestampNs(2))?,
        &context,
    )?;
    let leaf = ContentDigest::sha256(&[7]);

    // A real completed retained import supplies the unrelated deletion closure.
    let frame = fs::read(fixture("jpeg/gray_16x16_flat.jpg")?)?;
    let input = dir.join("source.mjpeg");
    fs::write(&input, frame.repeat(2))?;
    let receipt = FileIngestAdapter::ingest(
        request(&input, frame.len() as u64, 8)?,
        &context,
        &mut deployment,
    )?;
    let plan = plan_deletion(&deployment, receipt.import_identity, &context)?;
    if !plan.blockers.is_empty() {
        return Err("test deletion unexpectedly blocked".into());
    }
    let plan_digest = plan.digest()?;
    let deleted: Vec<_> = plan.deletable.iter().map(|object| object.digest).collect();
    let approval = plan.approval_digest(PRINCIPAL)?;
    let _ = commit_deletion(
        &mut deployment,
        plan_digest,
        approval,
        PRINCIPAL,
        &context,
    )?;

    Ok(Harness {
        deployment,
        selected: vec![slot],
        leaf,
        import: receipt.import_identity,
        plan_digest,
        deleted,
    })
}

fn never_cancel() -> bool { false }
static NEVER_CANCEL: fn() -> bool = never_cancel;

fn request_for<'a>(
    slots: &'a [SlotName],
    denied: &'a BTreeMap<ContentDigest, ContentDigest>,
) -> DurableBeliefRequest<'a, fn() -> bool> {
    DurableBeliefRequest {
        slots,
        denied,
        limits: DurableBeliefLimits::default(),
        cancelled: &NEVER_CANCEL,
    }
}

#[test]
fn unrelated_committed_deletion_no_longer_disables_intact_durable_beliefs() -> TestResult {
    let h = harness("belief-deletion-survives")?;
    let offered = make_belief(h.deployment.current_anchor(), h.leaf)?;
    let denied = BTreeMap::new();

    // The legacy/default entry remains fail-closed until a deletion owner is explicitly selected.
    assert!(matches!(
        verify_durable_belief(
            &offered.canonical_bytes(),
            h.deployment.ledger(),
            h.deployment.publisher(),
            &HostSpoolIo,
            &ByteEngine,
            request_for(&h.selected, &denied),
        ),
        Err(DurableBeliefError::DeletionAdapterRequired)
    ));

    let verified = verify_durable_belief_with_committed_deletions(
        &offered.canonical_bytes(),
        &h.deployment,
        &HostSpoolIo,
        &ByteEngine,
        request_for(&h.selected, &denied),
    )?;
    assert_eq!(verified.belief(), &offered);
    assert!(verified.custody_audit().all_verified());
    assert!(!verified
        .to_knowledge_cell(&|| false)?
        .is_irreversible_effect_premise(TimestampNs(2)));

    // The deletion owner returns every deleted spool object and does not deny unrelated custody.
    let map = DurableBeliefDeletionAuthority::verified_denials(
        &CommittedDeletionBeliefAuthority,
        h.deployment.ledger(),
        h.deployment.publisher(),
    )?;
    assert!(!map.contains_key(&h.leaf));
    assert!(!h.deleted.is_empty());
    for digest in &h.deleted {
        assert_eq!(map.get(digest), Some(&h.plan_digest));
    }
    assert!(map.values().all(|proof| *proof == h.plan_digest));
    let _ = h.import; // identity remains historical authority; its content was deleted.
    Ok(())
}

#[test]
fn malformed_deletion_markers_cannot_use_the_owner_adapter_as_a_bypass() -> TestResult {
    let mut h = harness("belief-deletion-forged-history")?;
    let context = cx("belief-deletion-forged-history-append")?;
    // A reserved-looking orphan marker is not a valid deletion proof sequence. The durable core
    // can append an empty generic batch, but the deletion owner must reject its history.
    let _ = h.deployment.append_batch(
        BatchId::parse("batch:deletion:forged-orphan")?,
        vec![],
        vec![],
        &context,
    )?;
    let offered = make_belief(h.deployment.current_anchor(), h.leaf)?;
    let denied = BTreeMap::new();
    assert!(matches!(
        verify_durable_belief_with_committed_deletions(
            &offered.canonical_bytes(),
            &h.deployment,
            &HostSpoolIo,
            &ByteEngine,
            request_for(&h.selected, &denied),
        ),
        Err(DurableBeliefError::DeletionAuthorityInvalid)
    ));
    Ok(())
}

#[test]
fn explicit_denials_cannot_disagree_with_committed_deletion_proof_identity() -> TestResult {
    let h = harness("belief-deletion-denial-conflict")?;
    let offered = make_belief(h.deployment.current_anchor(), h.leaf)?;
    let target = *h.deleted.first().ok_or("expected deleted object")?;
    let conflicting = BTreeMap::from([(
        target,
        ContentDigest::sha256(b"not-the-committed-deletion-plan"),
    )]);
    assert!(matches!(
        verify_durable_belief_with_committed_deletions(
            &offered.canonical_bytes(),
            &h.deployment,
            &HostSpoolIo,
            &ByteEngine,
            request_for(&h.selected, &conflicting),
        ),
        Err(DurableBeliefError::DeletionAuthorityInvalid)
    ));
    Ok(())
}
