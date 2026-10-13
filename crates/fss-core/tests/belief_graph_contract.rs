#![forbid(unsafe_code)]
//! Deterministic graph-provenance, resource and cancellation contracts.
use std::cell::Cell;
use std::collections::BTreeMap;

use fss_core::belief_verification::graph::{
    BeliefGraphError, BeliefGraphLimits, BeliefGraphRequest, RetainedBeliefGraph,
    verify_derived_belief_graph,
};
use fss_core::belief_verification::{
    BeliefEvidenceReadError, BeliefRebuildInputs, BeliefVerificationError,
    RegisteredBeliefDeriver, RetainedBeliefEvidence,
};
use fss_core::{
    BatchId, BeliefInterval, CanonicalEncoder, CaptureInterval, ContentDigest, ContractError,
    DerivedBelief, DerivedBeliefParams, EvidenceDelta, Generation, KnowledgeState, LedgerAnchor,
    ObjectId, Plane, ProvenanceClass, ReferenceLedger, TimestampNs,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Default)]
struct Graph {
    bytes: BTreeMap<ContentDigest, Vec<u8>>,
    edges: BTreeMap<ContentDigest, Vec<ContentDigest>>,
    reads: Cell<usize>,
}
impl Graph {
    fn leaf(&mut self, bytes: &[u8]) -> ContentDigest {
        let root = ContentDigest::sha256(bytes);
        self.bytes.insert(root, bytes.to_vec());
        root
    }
    fn node(&mut self, kind: &str, mut children: Vec<ContentDigest>) -> Result<ContentDigest, ContractError> {
        children.sort_unstable();
        let mut encoder = CanonicalEncoder::new();
        encoder.text(kind);
        for child in &children { encoder.digest(*child); }
        let bytes = encoder.finish_checked()?;
        let root = self.leaf(&bytes);
        self.edges.insert(root, children);
        Ok(root)
    }
}
impl RetainedBeliefEvidence for Graph {
    fn read_belief_evidence(&self, root: ContentDigest, max: usize) -> Result<Vec<u8>, BeliefEvidenceReadError> {
        self.reads.set(self.reads.get() + 1);
        let bytes = self.bytes.get(&root).ok_or(BeliefEvidenceReadError::Missing)?;
        if bytes.len() > max { return Err(BeliefEvidenceReadError::LimitExceeded); }
        Ok(bytes.clone())
    }
}
impl RetainedBeliefGraph for Graph {
    fn belief_children(&self, root: ContentDigest, bytes: &[u8], max: usize) -> Result<Vec<ContentDigest>, BeliefEvidenceReadError> {
        if self.bytes.get(&root).map(Vec::as_slice) != Some(bytes) { return Err(BeliefEvidenceReadError::Corrupt); }
        let children = self.edges.get(&root).map_or(&[][..], Vec::as_slice);
        if children.len() > max { return Err(BeliefEvidenceReadError::LimitExceeded); }
        Ok(children.to_vec())
    }
}

fn belief(anchor: &LedgerAnchor, support: ContentDigest, contradiction: ContentDigest, statement: &str) -> Result<DerivedBelief, ContractError> {
    DerivedBelief::new(DerivedBeliefParams {
        belief_id: "belief:graph:sum".to_owned(), anchor: anchor.clone(), generation: Generation(1),
        algorithm_id: "alg:graph-sum:v1".to_owned(), statement: statement.to_owned(),
        knowledge_state: KnowledgeState::Estimated, provenance: ProvenanceClass::Derived,
        uncertainty: BeliefInterval::new(200_000, 800_000)?, supporting_evidence: vec![support],
        contradictions: vec![contradiction], derivation_receipt: ContentDigest::sha256(b"unsealed"),
    }.with_computed_receipt()?)
}
#[derive(Default)]
struct Engine { calls: Cell<usize> }
impl RegisteredBeliefDeriver for Engine {
    fn algorithm_id(&self) -> &str { "alg:graph-sum:v1" }
    fn generation(&self) -> Generation { Generation(1) }
    fn derive(&self, input: &BeliefRebuildInputs<'_>) -> Result<DerivedBelief, ContractError> {
        self.calls.set(self.calls.get() + 1);
        let ([a], [b]) = (input.supporting, input.contradicting) else { return Err(ContractError::EvidenceRequired); };
        for evidence in [a, b] {
            if !evidence.bindings().is_empty() || evidence.ancestry().is_empty() { return Err(ContractError::EvidenceRequired); }
            for path in evidence.ancestry() {
                if path.revision().family != "fixture_graph"
                    || path.path().first() != Some(&path.revision().payload_digest)
                    || path.path().last() != Some(&evidence.digest()) {
                    return Err(ContractError::EvidenceRequired);
                }
            }
        }
        let ([a_byte], [b_byte]) = (a.bytes(), b.bytes()) else { return Err(ContractError::EvidenceRequired); };
        belief(input.anchor, a.digest(), b.digest(), &format!("sum {a_byte} minus {b_byte}"))
    }
}
struct Fixture {
    ledger: ReferenceLedger, graph: Graph, selected: Vec<ObjectId>,
    offered: DerivedBelief, root: ContentDigest, inner: ContentDigest, sibling: ContentDigest,
}
fn commit(ledger: &mut ReferenceLedger, id: &str, root: ContentDigest, plane: Plane) -> Result<(), ContractError> {
    let batch = ledger.prepare_batch(BatchId::parse(format!("batch:{id}"))?, vec![EvidenceDelta {
        delta_id: format!("delta:{id}"), family: "fixture_graph".to_owned(), object_id: ObjectId::parse(id)?,
        prior_generation: None, new_generation: 1, validity: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
        plane, payload_digest: root, witness_digest: None, operation_id: None,
    }], [root])?;
    let _ = ledger.append(batch)?;
    Ok(())
}
fn fixture() -> Result<Fixture, ContractError> {
    let mut graph = Graph::default();
    let a = graph.leaf(&[3]);
    let b = graph.leaf(&[1]);
    let sibling = graph.leaf(&[5]);
    let inner = graph.node("inner", vec![a, b])?;
    let root = graph.node("outer", vec![inner, sibling])?;
    let mut ledger = ReferenceLedger::new("site:graph");
    commit(&mut ledger, "object:a", root, Plane::Authority)?;
    let offered = belief(&ledger.current().anchor, a, b, "sum 3 minus 1")?;
    Ok(Fixture { ledger, graph, selected: vec![ObjectId::parse("object:a")?], offered, root, inner, sibling })
}
fn request(selected: &[ObjectId]) -> BeliefGraphRequest<'_> {
    BeliefGraphRequest { authority_objects: selected, limits: BeliefGraphLimits::default(), cancelled: &|| false }
}

#[test]
fn complete_transitive_closure_retains_typed_paths_not_fabricated_direct_bindings() -> TestResult {
    let f = fixture()?;
    let engine = Engine::default();
    let result = verify_derived_belief_graph(&f.offered, &f.ledger, &f.graph, &engine, request(&f.selected))?;
    let a = f.offered.supporting_evidence()[0];
    let paths = result.ancestry(a).ok_or("missing ancestry")?;
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].path(), &[f.root, f.inner, a]);
    assert_eq!(result.proof().belief(), &f.offered);
    assert!(!result.proof().to_knowledge_cell()?.is_irreversible_effect_premise(TimestampNs(20)));
    assert_eq!(result.usage().read_attempts, 5);
    assert_eq!(result.usage().visits, 5);
    assert_eq!(result.usage().edge_visits, 12);
    assert_eq!(result.usage().witness_steps, 6);
    assert_eq!(engine.calls.get(), 1);
    Ok(())
}

#[test]
fn a_missing_or_corrupt_unused_sibling_blocks_derivation() -> TestResult {
    for missing in [true, false] {
        let mut f = fixture()?;
        if missing { f.graph.bytes.remove(&f.sibling); } else { f.graph.bytes.insert(f.sibling, vec![9]); }
        let engine = Engine::default();
        let failure = verify_derived_belief_graph(&f.offered, &f.ledger, &f.graph, &engine, request(&f.selected)).err().ok_or("accepted damaged sibling")?;
        let expected = if missing { BeliefVerificationError::Read { digest: f.sibling, cause: BeliefEvidenceReadError::Missing } }
            else { BeliefVerificationError::PayloadDigestMismatch(f.sibling) };
        assert_eq!(failure.reason, BeliefGraphError::Verification(expected));
        assert_eq!(engine.calls.get(), 0);
        assert!(failure.usage.read_attempts > 0);
    }
    Ok(())
}

#[test]
fn shared_payloads_are_read_once_but_each_authority_path_is_preserved_and_priced() -> TestResult {
    let mut f = fixture()?;
    commit(&mut f.ledger, "object:b", f.inner, Plane::Authority)?;
    f.selected.push(ObjectId::parse("object:b")?);
    f.offered = belief(&f.ledger.current().anchor, f.offered.supporting_evidence()[0], f.offered.contradictions()[0], f.offered.statement())?;
    let engine = Engine::default();
    let result = verify_derived_belief_graph(&f.offered, &f.ledger, &f.graph, &engine, request(&f.selected))?;
    let a = f.offered.supporting_evidence()[0];
    let paths = result.ancestry(a).ok_or("missing ancestry")?;
    assert_eq!(paths.len(), 2);
    assert_eq!(paths[0].object_id(), &f.selected[0]);
    assert_eq!(paths[1].object_id(), &f.selected[1]);
    assert_eq!(paths[1].path(), &[f.inner, a]);
    assert_eq!(result.usage().read_attempts, 5);
    assert_eq!(f.graph.reads.get(), 5);
    assert_eq!(result.usage().visits, 8);
    assert_eq!(result.usage().edge_visits, 14);
    assert_eq!(result.usage().witness_steps, 10);
    Ok(())
}

#[test]
fn selection_is_validated_completely_before_reading_or_expanding() -> TestResult {
    let f = fixture()?;
    let engine = Engine::default();
    for (ids, expected) in [
        (vec![], BeliefGraphError::InvalidSelection),
        (vec![f.selected[0].clone(), f.selected[0].clone()], BeliefGraphError::InvalidSelection),
        (vec![f.selected[0].clone(), ObjectId::parse("object:missing")?], BeliefGraphError::InvalidAuthorityObject(ObjectId::parse("object:missing")?)),
    ] {
        let failure = verify_derived_belief_graph(&f.offered, &f.ledger, &f.graph, &engine, request(&ids)).err().ok_or("bad selection accepted")?;
        assert_eq!(failure.reason, expected);
        assert_eq!(failure.usage.read_attempts, 0);
    }
    assert_eq!(f.graph.reads.get(), 0);
    Ok(())
}

#[test]
fn unselected_and_cognition_roots_do_not_grant_transitive_membership() -> TestResult {
    let mut f = fixture()?;
    commit(&mut f.ledger, "object:b", f.sibling, Plane::Authority)?;
    commit(&mut f.ledger, "object:c", f.root, Plane::Cognition)?;
    f.offered = belief(&f.ledger.current().anchor, f.offered.supporting_evidence()[0], f.offered.contradictions()[0], f.offered.statement())?;
    let engine = Engine::default();
    let ids = [ObjectId::parse("object:b")?];
    let failure = verify_derived_belief_graph(&f.offered, &f.ledger, &f.graph, &engine, request(&ids)).err().ok_or("unselected root accepted")?;
    assert!(matches!(failure.reason, BeliefGraphError::Verification(BeliefVerificationError::RootNotAnchored(_))));
    let ids = [ObjectId::parse("object:c")?];
    let failure = verify_derived_belief_graph(&f.offered, &f.ledger, &f.graph, &engine, request(&ids)).err().ok_or("cognition root accepted")?;
    assert_eq!(failure.reason, BeliefGraphError::InvalidAuthorityObject(ids[0].clone()));
    assert_eq!(failure.usage.read_attempts, 0);
    assert_eq!(engine.calls.get(), 0);
    Ok(())
}

#[test]
fn traversal_limits_refuse_without_a_partial_or_unpriced_proof() -> TestResult {
    let f = fixture()?;
    let engine = Engine::default();
    for (limits, dimension) in [
        (BeliefGraphLimits { max_authority_objects: 0, ..Default::default() }, "authority objects"),
        (BeliefGraphLimits { max_graph_objects: 4, ..Default::default() }, "objects"),
        (BeliefGraphLimits { max_visits: 4, ..Default::default() }, "visits"),
        (BeliefGraphLimits { max_edge_visits: 11, ..Default::default() }, "edges"),
        (BeliefGraphLimits { max_depth: 1, ..Default::default() }, "depth"),
        (BeliefGraphLimits { max_witness_steps: 5, ..Default::default() }, "witness steps"),
    ] {
        let failure = verify_derived_belief_graph(&f.offered, &f.ledger, &f.graph, &engine, BeliefGraphRequest { limits, ..request(&f.selected) }).err().ok_or("exhausted graph accepted")?;
        assert_eq!(failure.reason, BeliefGraphError::Limit(dimension));
        assert_eq!(failure.usage.derivations, 0);
    }
    let limits = BeliefGraphLimits { max_authority_objects: 1, max_graph_objects: 5, max_visits: 5, max_edge_visits: 12, max_depth: 2, max_witness_steps: 6, ..Default::default() };
    assert!(verify_derived_belief_graph(&f.offered, &f.ledger, &f.graph, &engine, BeliefGraphRequest { limits, ..request(&f.selected) }).is_ok());
    Ok(())
}

#[test]
fn byte_limits_include_ancestor_and_sibling_payloads_not_only_offered_evidence() -> TestResult {
    let f = fixture()?;
    let engine = Engine::default();
    let mut limits = BeliefGraphLimits::default();
    let bytes: usize = f.graph.bytes.values().map(Vec::len).sum();
    limits.verification.max_total_bytes = bytes - 1;
    let failure = verify_derived_belief_graph(&f.offered, &f.ledger, &f.graph, &engine, BeliefGraphRequest { limits, ..request(&f.selected) }).err().ok_or("byte overrun accepted")?;
    assert!(matches!(failure.reason, BeliefGraphError::Verification(BeliefVerificationError::Read { cause: BeliefEvidenceReadError::LimitExceeded, .. })));
    assert_eq!(engine.calls.get(), 0);
    limits.verification.max_total_bytes = bytes;
    let result = verify_derived_belief_graph(&f.offered, &f.ledger, &f.graph, &engine, BeliefGraphRequest { limits, ..request(&f.selected) })?;
    assert_eq!(result.usage().admitted_bytes, bytes);
    Ok(())
}

#[test]
fn cancellation_before_reads_during_walk_and_after_derivation_never_mints_a_proof() -> TestResult {
    for phase in 0..3 {
        let f = fixture()?;
        let engine = Engine::default();
        let cancel = || match phase { 0 => true, 1 => f.graph.reads.get() > 0, _ => engine.calls.get() > 0 };
        let failure = verify_derived_belief_graph(&f.offered, &f.ledger, &f.graph, &engine, BeliefGraphRequest { cancelled: &cancel, ..request(&f.selected) }).err().ok_or("cancelled graph accepted")?;
        assert_eq!(failure.reason, BeliefGraphError::Cancelled);
        assert_eq!(failure.usage.derivations, usize::from(phase == 2));
        if phase == 0 { assert_eq!(failure.usage.read_attempts, 0); }
        if phase == 1 { assert_eq!(failure.usage.read_attempts, 1); }
    }
    Ok(())
}

#[test]
fn noncanonical_edges_and_cycles_are_rejected_without_deriving() -> TestResult {
    for cycle in [false, true] {
        let mut f = fixture()?;
        let edges = f.graph.edges.get_mut(&f.root).ok_or("no root edges")?;
        if cycle { edges.push(f.root); edges.sort_unstable(); } else { edges.push(edges[0]); }
        let engine = Engine::default();
        let failure = verify_derived_belief_graph(&f.offered, &f.ledger, &f.graph, &engine, request(&f.selected)).err().ok_or("malformed graph accepted")?;
        assert!(matches!(failure.reason, BeliefGraphError::InvalidGraph(_)));
        assert_eq!(engine.calls.get(), 0);
    }
    Ok(())
}

#[test]
fn current_anchor_and_independent_derivation_remain_mandatory_for_graph_beliefs() -> TestResult {
    let mut f = fixture()?;
    let engine = Engine::default();
    let forged = belief(f.offered.anchor(), f.offered.supporting_evidence()[0], f.offered.contradictions()[0], "invented conclusion")?;
    let failure = verify_derived_belief_graph(&forged, &f.ledger, &f.graph, &engine, request(&f.selected)).err().ok_or("forged conclusion accepted")?;
    assert_eq!(failure.reason, BeliefGraphError::Verification(BeliefVerificationError::DerivationMismatch));
    let batch = f.ledger.prepare_batch(BatchId::parse("batch:advance")?, vec![], [])?;
    let _ = f.ledger.append(batch)?;
    let failure = verify_derived_belief_graph(&f.offered, &f.ledger, &f.graph, &engine, request(&f.selected)).err().ok_or("stale graph accepted")?;
    assert_eq!(failure.reason, BeliefGraphError::Verification(BeliefVerificationError::Contract(ContractError::StaleAnchor)));
    assert_eq!(failure.usage.read_attempts, 0);
    Ok(())
}
