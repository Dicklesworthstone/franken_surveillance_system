#![forbid(unsafe_code)]
//! Native store publication, cold reconstitution and deletion regression contracts.

use std::cell::Cell;

use fss_core::belief_verification::graph::{BeliefGraphLimits, verify_derived_belief_graph};
use fss_core::belief_verification::{BeliefRebuildInputs, BeliefVerificationError};
use fss_core::{
    BatchId, BeliefInterval, CanonicalEncode, CaptureInterval, ContractError, DerivedBeliefParams,
    EvidenceDelta, Generation, KnowledgeState, LedgerAnchor, ObjectId, Plane, ProvenanceClass,
    TimestampNs, TombstoneReason, TombstoneRecord,
};

use super::*;
use crate::{ObjectError, ObjectLimits};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Default)]
struct Engine {
    calls: Cell<usize>,
}

fn belief(
    anchor: &LedgerAnchor,
    evidence: ContentDigest,
    statement: &str,
) -> Result<DerivedBelief, ContractError> {
    DerivedBelief::new(
        DerivedBeliefParams {
            belief_id: "belief:published-byte".to_owned(),
            anchor: anchor.clone(),
            generation: Generation(1),
            algorithm_id: "alg:published-byte:v1".to_owned(),
            statement: statement.to_owned(),
            knowledge_state: KnowledgeState::Estimated,
            provenance: ProvenanceClass::Derived,
            uncertainty: BeliefInterval::new(200_000, 800_000)?,
            supporting_evidence: vec![evidence],
            contradictions: vec![],
            derivation_receipt: ContentDigest::sha256(b"unsealed"),
        }
        .with_computed_receipt()?,
    )
}

impl RegisteredBeliefDeriver for Engine {
    fn algorithm_id(&self) -> &str {
        "alg:published-byte:v1"
    }
    fn generation(&self) -> Generation {
        Generation(1)
    }
    fn derive(&self, input: &BeliefRebuildInputs<'_>) -> Result<DerivedBelief, ContractError> {
        self.calls.set(self.calls.get() + 1);
        let [evidence] = input.supporting else {
            return Err(ContractError::EvidenceRequired);
        };
        let [ancestry] = evidence.ancestry() else {
            return Err(ContractError::EvidenceRequired);
        };
        if input.belief_id != "belief:published-byte"
            || !input.contradicting.is_empty()
            || !evidence.bindings().is_empty()
            || evidence.bytes() != [42]
            || ancestry.object_id().as_str() != "object:published-source"
            || ancestry.revision().family != "published_source"
            || ancestry.revision().generation != 1
            || ancestry.revision().validity
                != CaptureInterval::new(TimestampNs(10), TimestampNs(20))?
            || ancestry.path().first() != Some(&ancestry.revision().payload_digest)
            || ancestry.path().last() != Some(&evidence.digest())
            || ancestry.path().len() < 2
        {
            return Err(ContractError::EvidenceRequired);
        }
        belief(
            input.anchor,
            evidence.digest(),
            "published source byte is 42",
        )
    }
}

struct Fixture {
    store: InMemoryObjectStore,
    ledger: ReferenceLedger,
    selected: Vec<ObjectId>,
    offered: DerivedBelief,
    leaf: ContentDigest,
    metadata: ContentDigest,
    inner: ObjectManifest,
    outer: ObjectManifest,
}

fn ledger_for(root: ContentDigest) -> Result<ReferenceLedger, ContractError> {
    let mut ledger = ReferenceLedger::new("site:published-graph");
    let batch = ledger.prepare_batch(
        BatchId::parse("batch:published-source")?,
        vec![EvidenceDelta {
            delta_id: "delta:published-source".to_owned(),
            family: "published_source".to_owned(),
            object_id: ObjectId::parse("object:published-source")?,
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
            plane: Plane::Authority,
            payload_digest: root,
            witness_digest: None,
            operation_id: None,
        }],
        [root],
    )?;
    let _ = ledger.append(batch)?;
    Ok(ledger)
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let mut store = InMemoryObjectStore::new(ObjectLimits::default());
    let leaf = store.put_verified(&[42])?;
    let metadata = store.put_verified(b"exact source metadata")?;
    let inner = ObjectManifest::new("source", [leaf], Some(metadata))?;
    let _ = store.publish_manifest(inner.clone())?;
    let outer = ObjectManifest::new("event_evidence", [inner.root()], None)?;
    let _ = store.publish_manifest(outer.clone())?;
    let ledger = ledger_for(outer.root())?;
    let selected = vec![ObjectId::parse("object:published-source")?];
    let offered = belief(
        &ledger.current().anchor,
        leaf,
        "published source byte is 42",
    )?;
    Ok(Fixture {
        store,
        ledger,
        selected,
        offered,
        leaf,
        metadata,
        inner,
        outer,
    })
}

fn request(ids: &[ObjectId]) -> BeliefGraphRequest<'_> {
    BeliefGraphRequest {
        authority_objects: ids,
        limits: BeliefGraphLimits::default(),
        cancelled: &|| false,
    }
}

fn intake<'a>(
    bytes: &[u8],
    f: &'a Fixture,
    engine: &'a Engine,
) -> Result<VerifiedBeliefGraph<'a>, BeliefGraphFailure> {
    f.store.decode_and_verify_belief_graph(
        bytes,
        &f.ledger,
        engine,
        request(&f.selected),
        256 * 1024,
    )
}

#[test]
fn published_nested_graph_intake_is_exact_and_nonmutating() -> TestResult {
    let f = fixture()?;
    let before = (
        f.store.objects.clone(),
        f.store.visible_manifests.clone(),
        f.store.total_bytes(),
    );
    let engine = Engine::default();
    let bytes = f.offered.try_canonical_bytes()?;
    let verified = intake(&bytes, &f, &engine)?;
    assert_eq!(verified.proof().belief(), &f.offered);
    assert_eq!(
        verified.ancestry(f.leaf).ok_or("missing ancestry")?[0].path(),
        &[f.outer.root(), f.inner.root(), f.leaf]
    );
    assert_eq!(verified.usage().read_attempts, 4);
    assert_eq!(verified.usage().visits, 4);
    assert_eq!(verified.usage().edge_visits, 9);
    assert_eq!(engine.calls.get(), 1);
    assert!(
        !verified
            .proof()
            .to_knowledge_cell()?
            .is_irreversible_effect_premise(TimestampNs(20))
    );
    assert_eq!(
        before,
        (
            f.store.objects.clone(),
            f.store.visible_manifests.clone(),
            f.store.total_bytes()
        )
    );
    assert_eq!(f.ledger.batches().len(), 1);
    Ok(())
}

#[test]
fn saved_manifest_bytes_do_not_implicitly_restore_publication_or_child_membership() -> TestResult {
    let f = fixture()?;
    let engine = Engine::default();
    let mut cold = InMemoryObjectStore::new(ObjectLimits::default());
    for root in [f.leaf, f.metadata, f.inner.root(), f.outer.root()] {
        assert_eq!(cold.put_verified(f.store.read_verified(root)?)?, root);
    }
    assert_eq!(cold.published_manifest_count(), 0);
    let failure = cold
        .decode_and_verify_belief_graph(
            &f.offered.try_canonical_bytes()?,
            &f.ledger,
            &engine,
            request(&f.selected),
            256 * 1024,
        )
        .err()
        .ok_or("unpublished graph accepted")?;
    assert_eq!(
        failure.reason,
        BeliefGraphError::Verification(BeliefVerificationError::RootNotAnchored(f.leaf))
    );
    assert_eq!(failure.usage.read_attempts, 1);
    assert_eq!(cold.published_manifest_count(), 0);
    assert_eq!(engine.calls.get(), 0);
    Ok(())
}

#[test]
fn cold_replay_needs_explicit_bottom_up_publication_then_rederives_the_same_result() -> TestResult {
    let f = fixture()?;
    let ledger = ReferenceLedger::replay("site:published-graph", f.ledger.batches().to_vec())?;
    let mut cold = InMemoryObjectStore::new(ObjectLimits::default());
    let engine = Engine::default();
    let encoded = f.offered.try_canonical_bytes()?;
    let failure = cold
        .decode_and_verify_belief_graph(
            &encoded,
            &ledger,
            &engine,
            request(&f.selected),
            encoded.len(),
        )
        .err()
        .ok_or("empty custody accepted")?;
    assert_eq!(
        failure.reason,
        BeliefGraphError::Verification(BeliefVerificationError::Read {
            digest: f.outer.root(),
            cause: BeliefEvidenceReadError::Missing
        })
    );
    assert_eq!(cold.object_count(), 0);
    for root in [f.leaf, f.metadata] {
        assert_eq!(cold.put_verified(f.store.read_verified(root)?)?, root);
    }
    assert!(matches!(
        cold.publish_manifest(f.outer.clone()),
        Err(ObjectError::Missing(_))
    ));
    let _ = cold.publish_manifest(ObjectManifest::from_canonical_bytes(
        f.store.read_verified(f.inner.root())?,
    )?)?;
    let _ = cold.publish_manifest(ObjectManifest::from_canonical_bytes(
        f.store.read_verified(f.outer.root())?,
    )?)?;
    let verified = cold.decode_and_verify_belief_graph(
        &encoded,
        &ledger,
        &engine,
        request(&f.selected),
        encoded.len(),
    )?;
    assert_eq!(verified.proof().belief(), &f.offered);
    assert_eq!(
        verified.ancestry(f.leaf).ok_or("no cold path")?[0].path(),
        &[f.outer.root(), f.inner.root(), f.leaf]
    );
    assert_eq!(engine.calls.get(), 1);
    Ok(())
}

#[test]
fn corrupt_ancestors_and_unused_metadata_block_intake_before_the_engine() -> TestResult {
    for selector in 0..3 {
        let mut f = fixture()?;
        let root = match selector {
            0 => f.outer.root(),
            1 => f.inner.root(),
            _ => f.metadata,
        };
        f.store.corrupt_for_test(root)?;
        let corrupted = f.store.objects.clone();
        let engine = Engine::default();
        let failure = intake(&f.offered.try_canonical_bytes()?, &f, &engine)
            .err()
            .ok_or("corrupt closure accepted")?;
        assert_eq!(
            failure.reason,
            BeliefGraphError::Verification(BeliefVerificationError::Read {
                digest: root,
                cause: BeliefEvidenceReadError::Corrupt
            })
        );
        assert_eq!(engine.calls.get(), 0);
        assert_eq!(f.store.objects, corrupted);
    }
    Ok(())
}

#[test]
fn owner_deletion_invalidates_ancestors_without_turning_them_into_opaque_leaves() -> TestResult {
    let mut f = fixture()?;
    let witness = f.store.put_verified(b"explicit owner deletion authority")?;
    f.store.tombstone(
        f.metadata,
        TombstoneRecord::new(
            ObjectId::parse("object:source-metadata")?,
            Generation(2),
            Generation(1),
            TombstoneReason::Deleted,
            Some(witness),
            f.metadata,
        )?,
    )?;
    assert_eq!(f.store.state(f.outer.root()), Some(ObjectState::Verified));
    assert_eq!(f.store.state(f.inner.root()), Some(ObjectState::Verified));
    assert_eq!(f.store.read_verified(f.leaf)?, &[42]);
    assert_eq!(f.store.published_manifest_count(), 0);
    let engine = Engine::default();
    let failure = intake(&f.offered.try_canonical_bytes()?, &f, &engine)
        .err()
        .ok_or("invalidated graph accepted")?;
    assert_eq!(
        failure.reason,
        BeliefGraphError::Verification(BeliefVerificationError::Read {
            digest: f.outer.root(),
            cause: BeliefEvidenceReadError::NotVerified
        })
    );
    assert_eq!(failure.usage.read_attempts, 1);
    assert_eq!(engine.calls.get(), 0);
    assert!(f.store.is_tombstoned(f.metadata));
    assert!(matches!(
        f.store.put_verified(b"exact source metadata"),
        Err(ObjectError::Tombstoned(_))
    ));
    Ok(())
}

#[test]
fn unpublished_manifest_looking_child_is_opaque_even_inside_a_published_parent() -> TestResult {
    let mut f = fixture()?;
    f.store = InMemoryObjectStore::new(ObjectLimits::default());
    let _ = f.store.put_verified(&[42])?;
    let _ = f.store.put_verified(b"exact source metadata")?;
    assert_eq!(
        f.store.put_verified(&f.inner.try_canonical_bytes()?)?,
        f.inner.root()
    );
    let _ = f.store.publish_manifest(f.outer.clone())?;
    assert_eq!(f.store.published_manifest_count(), 1);
    assert!(
        f.store
            .belief_children(f.inner.root(), f.store.read_verified(f.inner.root())?, 0)?
            .is_empty()
    );
    let engine = Engine::default();
    let failure = intake(&f.offered.try_canonical_bytes()?, &f, &engine)
        .err()
        .ok_or("sniffed unpublished child")?;
    assert_eq!(
        failure.reason,
        BeliefGraphError::Verification(BeliefVerificationError::RootNotAnchored(f.leaf))
    );
    assert_eq!(failure.usage.read_attempts, 2);
    assert_eq!(engine.calls.get(), 0);
    assert_eq!(f.store.published_manifest_count(), 1);
    Ok(())
}

#[test]
fn cached_publication_cannot_substitute_a_different_typed_manifest() -> TestResult {
    let mut f = fixture()?;
    let replacement = ObjectManifest::new("different_kind", [f.inner.root()], None)?;
    f.store
        .visible_manifests
        .insert(f.outer.root(), replacement);
    let engine = Engine::default();
    let failure = intake(&f.offered.try_canonical_bytes()?, &f, &engine)
        .err()
        .ok_or("cache swap accepted")?;
    assert_eq!(
        failure.reason,
        BeliefGraphError::Verification(BeliefVerificationError::Read {
            digest: f.outer.root(),
            cause: BeliefEvidenceReadError::Corrupt
        })
    );
    assert_eq!(engine.calls.get(), 0);
    Ok(())
}

#[test]
fn graph_owner_checks_actual_bytes_and_both_edge_counts_before_decoding() -> TestResult {
    let mut f = fixture()?;
    let bytes = f.inner.try_canonical_bytes()?;
    assert_eq!(
        f.store.belief_children(f.inner.root(), &bytes, 1),
        Err(BeliefEvidenceReadError::LimitExceeded)
    );
    assert_eq!(
        f.store.belief_children(f.inner.root(), &bytes, 2)?,
        f.inner.children()
    );
    assert_eq!(
        f.store.belief_children(f.inner.root(), b"swapped", 2),
        Err(BeliefEvidenceReadError::Corrupt)
    );
    // Plant a smaller cached list. The actual encoded list must still be bounded before allocation.
    f.store
        .visible_manifests
        .insert(f.inner.root(), ObjectManifest::new("source", [], None)?);
    assert_eq!(
        f.store.belief_children(f.inner.root(), &bytes, 1),
        Err(BeliefEvidenceReadError::LimitExceeded)
    );
    assert_eq!(
        f.store.belief_children(f.inner.root(), &bytes, 2),
        Err(BeliefEvidenceReadError::Corrupt)
    );
    Ok(())
}

#[test]
fn canonical_graph_intake_rejects_every_truncation_trailing_bytes_and_oversize_input() -> TestResult
{
    let f = fixture()?;
    let bytes = f.offered.try_canonical_bytes()?;
    let engine = Engine::default();
    let failure = f
        .store
        .decode_and_verify_belief_graph(
            &bytes,
            &f.ledger,
            &engine,
            request(&f.selected),
            bytes.len() - 1,
        )
        .err()
        .ok_or("encoded limit bypassed")?;
    assert_eq!(failure.reason, BeliefGraphError::Limit("encoded bytes"));
    assert_eq!(failure.usage, BeliefGraphUsage::default());
    for end in 0..bytes.len() {
        let failure = intake(&bytes[..end], &f, &engine)
            .err()
            .ok_or("truncated belief accepted")?;
        assert!(matches!(
            failure.reason,
            BeliefGraphError::Verification(BeliefVerificationError::Contract(_))
        ));
        assert_eq!(failure.usage, BeliefGraphUsage::default());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(intake(&trailing, &f, &engine).is_err());
    assert_eq!(engine.calls.get(), 0);
    assert!(
        f.store
            .decode_and_verify_belief_graph(
                &bytes,
                &f.ledger,
                &engine,
                request(&f.selected),
                bytes.len()
            )
            .is_ok()
    );
    assert_eq!(engine.calls.get(), 1);
    Ok(())
}

#[test]
fn cancellation_and_closure_byte_limits_never_promote_or_mutate_custody() -> TestResult {
    let f = fixture()?;
    let engine = Engine::default();
    let encoded = f.offered.try_canonical_bytes()?;
    let before = (
        f.store.objects.clone(),
        f.store.visible_manifests.clone(),
        f.store.total_bytes(),
    );
    let failure = f
        .store
        .decode_and_verify_belief_graph(
            &encoded,
            &f.ledger,
            &engine,
            BeliefGraphRequest {
                cancelled: &|| true,
                ..request(&f.selected)
            },
            encoded.len(),
        )
        .err()
        .ok_or("cancel ignored")?;
    assert_eq!(failure.reason, BeliefGraphError::Cancelled);
    assert_eq!(failure.usage, BeliefGraphUsage::default());
    let required = usize::try_from(f.store.total_bytes())?;
    let mut limits = BeliefGraphLimits::default();
    limits.verification.max_total_bytes = required - 1;
    let failure = f
        .store
        .decode_and_verify_belief_graph(
            &encoded,
            &f.ledger,
            &engine,
            BeliefGraphRequest {
                limits,
                ..request(&f.selected)
            },
            encoded.len(),
        )
        .err()
        .ok_or("underpriced graph accepted")?;
    assert!(matches!(
        failure.reason,
        BeliefGraphError::Verification(BeliefVerificationError::Read {
            cause: BeliefEvidenceReadError::LimitExceeded,
            ..
        })
    ));
    assert_eq!(engine.calls.get(), 0);
    limits.verification.max_total_bytes = required;
    let verified = f.store.decode_and_verify_belief_graph(
        &encoded,
        &f.ledger,
        &engine,
        BeliefGraphRequest {
            limits,
            ..request(&f.selected)
        },
        encoded.len(),
    )?;
    assert_eq!(verified.usage().admitted_bytes, required);
    assert_eq!(
        before,
        (
            f.store.objects.clone(),
            f.store.visible_manifests.clone(),
            f.store.total_bytes()
        )
    );
    Ok(())
}

#[test]
fn staged_and_tombstoned_roots_cannot_expose_graph_edges() -> TestResult {
    let f = fixture()?;
    let bytes = f.inner.try_canonical_bytes()?;
    let mut store = InMemoryObjectStore::new(ObjectLimits::default());
    let root = store.stage(&bytes)?;
    assert_eq!(
        store.belief_children(root, &bytes, 2),
        Err(BeliefEvidenceReadError::NotVerified)
    );
    assert_eq!(store.state(root), Some(ObjectState::Staged));
    store.verify(root)?;
    let witness = store.put_verified(b"owner tombstone authority")?;
    store.tombstone(
        root,
        TombstoneRecord::new(
            ObjectId::parse("object:manifest")?,
            Generation(2),
            Generation(1),
            TombstoneReason::Deleted,
            Some(witness),
            root,
        )?,
    )?;
    assert_eq!(
        store.belief_children(root, &bytes, 2),
        Err(BeliefEvidenceReadError::Missing)
    );
    Ok(())
}

#[test]
fn surviving_payloads_do_not_rescue_forged_conclusions_or_stale_anchors() -> TestResult {
    let mut f = fixture()?;
    let engine = Engine::default();
    let forged = belief(f.offered.anchor(), f.leaf, "owner-approved safe area")?;
    let failure =
        verify_derived_belief_graph(&forged, &f.ledger, &f.store, &engine, request(&f.selected))
            .err()
            .ok_or("forgery accepted")?;
    assert_eq!(
        failure.reason,
        BeliefGraphError::Verification(BeliefVerificationError::DerivationMismatch)
    );
    let batch = f
        .ledger
        .prepare_batch(BatchId::parse("batch:later")?, vec![], [])?;
    let _ = f.ledger.append(batch)?;
    let failure = intake(&f.offered.try_canonical_bytes()?, &f, &engine)
        .err()
        .ok_or("stale belief accepted")?;
    assert_eq!(
        failure.reason,
        BeliefGraphError::Verification(BeliefVerificationError::Contract(
            ContractError::StaleAnchor
        ))
    );
    assert_eq!(failure.usage.read_attempts, 0);
    assert_eq!(engine.calls.get(), 1);
    Ok(())
}
