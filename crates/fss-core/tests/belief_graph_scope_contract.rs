#![forbid(unsafe_code)]
//! Authority selection must fence metadata as well as transitive edge expansion.
use std::cell::Cell;

use fss_core::belief_verification::graph::{
    BeliefGraphError, BeliefGraphLimits, BeliefGraphRequest, RetainedBeliefGraph,
    verify_derived_belief_graph,
};
use fss_core::belief_verification::{
    BeliefEvidenceReadError, BeliefRebuildInputs, BeliefVerificationError, RegisteredBeliefDeriver,
    RetainedBeliefEvidence,
};
use fss_core::{
    BatchId, BeliefInterval, CaptureInterval, ContentDigest, ContractError, DerivedBelief,
    DerivedBeliefParams, EvidenceDelta, Generation, KnowledgeState, ObjectId, Plane,
    ProvenanceClass, ReferenceLedger, TimestampNs,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Reader {
    reads: Cell<usize>,
}
impl RetainedBeliefEvidence for Reader {
    fn read_belief_evidence(
        &self,
        root: ContentDigest,
        max: usize,
    ) -> Result<Vec<u8>, BeliefEvidenceReadError> {
        self.reads.set(self.reads.get() + 1);
        if root != ContentDigest::sha256(&[7]) {
            return Err(BeliefEvidenceReadError::Missing);
        }
        if max < 1 {
            return Err(BeliefEvidenceReadError::LimitExceeded);
        }
        Ok(vec![7])
    }
}
impl RetainedBeliefGraph for Reader {
    fn belief_children(
        &self,
        _: ContentDigest,
        _: &[u8],
        _: usize,
    ) -> Result<Vec<ContentDigest>, BeliefEvidenceReadError> {
        Ok(vec![])
    }
}

struct Engine {
    selected: Vec<ObjectId>,
    calls: Cell<usize>,
}
impl RegisteredBeliefDeriver for Engine {
    fn algorithm_id(&self) -> &str {
        "alg:scope-byte:v1"
    }
    fn generation(&self) -> Generation {
        Generation(1)
    }
    fn derive(&self, input: &BeliefRebuildInputs<'_>) -> Result<DerivedBelief, ContractError> {
        self.calls.set(self.calls.get() + 1);
        let [source] = input.supporting else {
            return Err(ContractError::EvidenceRequired);
        };
        if source.bytes() != [7]
            || !input.contradicting.is_empty()
            || source.bindings().len() != self.selected.len()
            || source.ancestry().len() != self.selected.len()
        {
            return Err(ContractError::EvidenceRequired);
        }
        // Exact arrays, not a contains check: any private extra row is a disclosure regression.
        for ((id, revision), expected) in source.bindings().iter().zip(&self.selected) {
            if id != expected || revision.family != "authorized_fixture" {
                return Err(ContractError::EvidenceRequired);
            }
        }
        for (ancestry, expected) in source.ancestry().iter().zip(&self.selected) {
            if ancestry.object_id() != expected || ancestry.path() != [source.digest()] {
                return Err(ContractError::EvidenceRequired);
            }
        }
        make_belief(input.anchor)
    }
}

fn make_belief(anchor: &fss_core::LedgerAnchor) -> Result<DerivedBelief, ContractError> {
    DerivedBelief::new(
        DerivedBeliefParams {
            belief_id: "belief:scoped-source".to_owned(),
            anchor: anchor.clone(),
            generation: Generation(1),
            algorithm_id: "alg:scope-byte:v1".to_owned(),
            statement: "selected source contains byte 7".to_owned(),
            knowledge_state: KnowledgeState::Estimated,
            provenance: ProvenanceClass::Derived,
            uncertainty: BeliefInterval::new(100_000, 900_000)?,
            supporting_evidence: vec![ContentDigest::sha256(&[7])],
            contradictions: vec![],
            derivation_receipt: ContentDigest::sha256(b"unsealed"),
        }
        .with_computed_receipt()?,
    )
}

fn fixture() -> Result<(ReferenceLedger, DerivedBelief, Reader), ContractError> {
    let mut ledger = ReferenceLedger::new("site:scoped-graph");
    let mut deltas = Vec::new();
    for (i, family) in [
        (0, "authorized_fixture"),
        (1, "authorized_fixture"),
        (2, "private_unselected_family"),
    ] {
        deltas.push(EvidenceDelta {
            delta_id: format!("delta:{i}"),
            object_id: ObjectId::parse(format!("object:{i}"))?,
            family: family.to_owned(),
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
            plane: Plane::Authority,
            payload_digest: ContentDigest::sha256(&[7]),
            witness_digest: None,
            operation_id: None,
        });
    }
    let batch = ledger.prepare_batch(BatchId::parse("batch:scoped")?, deltas, [])?;
    let _ = ledger.append(batch)?;
    let offered = make_belief(&ledger.current().anchor)?;
    Ok((
        ledger,
        offered,
        Reader {
            reads: Cell::new(0),
        },
    ))
}

#[test]
fn unselected_alias_metadata_is_not_disclosed_to_the_deriver() -> TestResult {
    let (ledger, offered, reader) = fixture()?;
    let selected = vec![ObjectId::parse("object:0")?];
    let engine = Engine {
        selected: selected.clone(),
        calls: Cell::new(0),
    };
    let verified = verify_derived_belief_graph(
        &offered,
        &ledger,
        &reader,
        &engine,
        BeliefGraphRequest {
            authority_objects: &selected,
            limits: BeliefGraphLimits::default(),
            cancelled: &|| false,
        },
    )?;
    assert_eq!(verified.proof().belief(), &offered);
    assert_eq!(verified.usage().snapshot_objects, 1);
    assert_eq!(reader.reads.get(), 1);
    assert_eq!(engine.calls.get(), 1);
    Ok(())
}

#[test]
fn unrelated_snapshot_rows_do_not_leak_through_scope_budgets_or_counters() -> TestResult {
    let (ledger, offered, reader) = fixture()?;
    let selected = vec![ObjectId::parse("object:0")?];
    let engine = Engine {
        selected: selected.clone(),
        calls: Cell::new(0),
    };
    let mut limits = BeliefGraphLimits::default();
    limits.verification.max_snapshot_objects = 1;
    let verified = verify_derived_belief_graph(
        &offered,
        &ledger,
        &reader,
        &engine,
        BeliefGraphRequest {
            authority_objects: &selected,
            limits,
            cancelled: &|| false,
        },
    )?;
    assert_eq!(verified.usage().snapshot_objects, 1);
    assert_eq!(verified.usage().authority_objects, 1);
    assert_eq!(verified.usage().read_attempts, 1);
    Ok(())
}

#[test]
fn all_explicitly_selected_aliases_are_preserved_but_not_private_ones() -> TestResult {
    let (ledger, offered, reader) = fixture()?;
    let selected = vec![ObjectId::parse("object:0")?, ObjectId::parse("object:1")?];
    let engine = Engine {
        selected: selected.clone(),
        calls: Cell::new(0),
    };
    let mut limits = BeliefGraphLimits::default();
    limits.verification.max_snapshot_objects = 1;
    let failure = verify_derived_belief_graph(
        &offered,
        &ledger,
        &reader,
        &engine,
        BeliefGraphRequest {
            authority_objects: &selected,
            limits,
            cancelled: &|| false,
        },
    )
    .err()
    .ok_or("scope inspection budget bypassed")?;
    assert_eq!(
        failure.reason,
        BeliefGraphError::Verification(BeliefVerificationError::SnapshotLimit)
    );
    assert_eq!(failure.usage.read_attempts, 0);
    assert_eq!(reader.reads.get(), 0);
    limits.verification.max_snapshot_objects = 2;
    let verified = verify_derived_belief_graph(
        &offered,
        &ledger,
        &reader,
        &engine,
        BeliefGraphRequest {
            authority_objects: &selected,
            limits,
            cancelled: &|| false,
        },
    )?;
    assert_eq!(verified.usage().snapshot_objects, 2);
    assert_eq!(verified.usage().visits, 2);
    assert_eq!(verified.usage().witness_steps, 2);
    assert_eq!(verified.usage().read_attempts, 1);
    assert_eq!(
        verified
            .ancestry(offered.supporting_evidence()[0])
            .ok_or("missing paths")?
            .len(),
        2
    );
    assert_eq!(engine.calls.get(), 1);
    Ok(())
}
