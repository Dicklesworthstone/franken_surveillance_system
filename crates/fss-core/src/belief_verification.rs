//! Evidence-backed verification of derived beliefs (PROV-002).
//!
//! A recomputed receipt proves encoding integrity, not provenance. This boundary additionally
//! requires authority-ledger membership, retained bytes, and an independent derivation. The ledger,
//! reader and registered engine are verifier-owned trust inputs; never build them from the claim.
//! The legacy `DerivedBelief::rebuild` and `to_knowledge_cell` remain structural operations and do
//! not return the private-field [`VerifiedDerivedBelief`] proof type.

/// Bounded transitive membership through a verifier-selected retained-object graph.
pub mod graph;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::{
    ContentDigest, ContractError, DerivedBelief, Generation, KnowledgeCell, LedgerAnchor, ObjectId,
    ObjectRevision, Plane, ReferenceLedger,
};

/// A retained-object read failed; missing or unverified bytes never count as evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeliefEvidenceReadError {
    /// No retained object exists.
    Missing,
    /// Bytes exist but have not passed custody verification.
    NotVerified,
    /// The retained object failed integrity verification.
    Corrupt,
    /// Reading the object would exceed the supplied byte allowance.
    LimitExceeded,
    /// The provider cannot currently establish availability.
    Unavailable,
}

impl fmt::Display for BeliefEvidenceReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Missing => "belief evidence is not retained",
            Self::NotVerified => "belief evidence is not custody-verified",
            Self::Corrupt => "belief evidence is corrupt",
            Self::LimitExceeded => "belief evidence exceeds the read allowance",
            Self::Unavailable => "belief evidence availability is unknown",
        })
    }
}

impl std::error::Error for BeliefEvidenceReadError {}

/// Read-only custody boundary. Implementations must enforce `max_bytes` before allocating a copy.
///
/// There is deliberately no permissive default or boolean existence shortcut. The verifier hashes
/// the returned bytes itself, and independently rejects an oversized response from a bad provider.
pub trait RetainedBeliefEvidence {
    /// Returns the exact custody-verified payload, without publishing or staging anything.
    fn read_belief_evidence(
        &self,
        digest: ContentDigest,
        max_bytes: usize,
    ) -> Result<Vec<u8>, BeliefEvidenceReadError>;
}

/// Deterministic bounds on membership lookup and retained-object reads.
///
/// The registered engine must additionally apply its own execution budget; these limits do not
/// purport to preempt arbitrary application code inside `RegisteredBeliefDeriver::derive`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BeliefVerificationLimits {
    /// Maximum objects in the authority snapshot inspected by the verifier.
    pub max_snapshot_objects: usize,
    /// Maximum supporting plus contradicting roots.
    pub max_roots: usize,
    /// Maximum retained bytes for a single root.
    pub max_root_bytes: usize,
    /// Maximum retained bytes across all roots.
    pub max_total_bytes: usize,
}

impl Default for BeliefVerificationLimits {
    fn default() -> Self {
        Self {
            max_snapshot_objects: 65_536,
            max_roots: 2_048,
            max_root_bytes: 16 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
        }
    }
}

/// An exact payload with every matching authority-object binding at the verified anchor.
///
/// Private fields prevent callers from substituting bytes or inventing a verified binding.
#[derive(Debug)]
pub struct VerifiedBeliefEvidence {
    digest: ContentDigest,
    bytes: Vec<u8>,
    bindings: Vec<(ObjectId, ObjectRevision)>,
    ancestry: Vec<graph::BeliefEvidenceAncestry>,
}

impl VerifiedBeliefEvidence {
    /// Algorithm-qualified identity of the payload.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// Independently rehashed retained bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Authority bindings in canonical object-ID order, including family and validity interval.
    ///
    /// A payload can be referenced by more than one object; no arbitrary first match is selected.
    #[must_use]
    pub fn bindings(&self) -> &[(ObjectId, ObjectRevision)] {
        &self.bindings
    }

    /// Explicit transitive paths from selected authority objects, never direct payload bindings.
    ///
    /// Empty for the direct verifier. Graph verification retains one deterministic shortest path
    /// per selected authority object. Engines must validate each ancestor's family and scope;
    /// an ancestor's family does not become the leaf payload's semantic type.
    #[must_use]
    pub fn ancestry(&self) -> &[graph::BeliefEvidenceAncestry] {
        &self.ancestry
    }
}

/// Inputs for an independent derivation. The claimed statement and confidence are NOT supplied.
pub struct BeliefRebuildInputs<'a> {
    /// Requested proposition identity, still subject to the engine's own semantic validation.
    pub belief_id: &'a str,
    /// Exact authority anchor independently selected by the verifier.
    pub anchor: &'a LedgerAnchor,
    /// Retained supporting payloads in canonical digest order.
    pub supporting: &'a [VerifiedBeliefEvidence],
    /// Retained contradicting payloads in canonical digest order.
    pub contradicting: &'a [VerifiedBeliefEvidence],
}

/// An independently selected, registered derivation implementation.
///
/// The caller must select this engine from its trusted registry, not accept an implementation or
/// registration supplied with the belief. Implementations must actually derive from the supplied
/// evidence, validate applicable families/scopes, and enforce their execution budgets. Merely
/// copying a previously offered belief does not implement this contract.
pub trait RegisteredBeliefDeriver {
    /// Registered algorithm identity, independent of the offered belief.
    fn algorithm_id(&self) -> &str;
    /// Registered generation, independent of the offered belief.
    fn generation(&self) -> Generation;
    /// Re-derives the complete result from verified evidence, including contradictions.
    fn derive(&self, inputs: &BeliefRebuildInputs<'_>) -> Result<DerivedBelief, ContractError>;
}

/// Exact, fail-closed reason a belief could not be independently verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BeliefVerificationError {
    /// Structural, freshness, or derivation-contract failure.
    Contract(ContractError),
    /// The independently registered algorithm does not match the claim.
    AlgorithmMismatch,
    /// The independently registered generation does not match the claim.
    GenerationMismatch,
    /// The snapshot exceeds the membership-inspection budget.
    SnapshotLimit,
    /// The combined evidence sets exceed the root budget.
    RootLimit,
    /// A root is not the payload of an authority object at the exact anchor.
    RootNotAnchored(ContentDigest),
    /// Custody could not supply verified bytes within budget.
    Read {
        /// Exact root whose read failed.
        digest: ContentDigest,
        /// Typed custody failure.
        cause: BeliefEvidenceReadError,
    },
    /// Returned bytes do not hash to the complete algorithm-qualified root.
    PayloadDigestMismatch(ContentDigest),
    /// The independently derived result differs from the offered result.
    DerivationMismatch,
}

impl fmt::Display for BeliefVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(f, "belief contract: {error}"),
            Self::AlgorithmMismatch => {
                f.write_str("belief algorithm is not the selected algorithm")
            }
            Self::GenerationMismatch => {
                f.write_str("belief generation is not the selected generation")
            }
            Self::SnapshotLimit => f.write_str("belief snapshot inspection budget exhausted"),
            Self::RootLimit => f.write_str("belief evidence root budget exhausted"),
            Self::RootNotAnchored(root) => {
                write!(f, "belief root is not authority-anchored: {root}")
            }
            Self::Read { digest, cause } => write!(f, "belief root {digest}: {cause}"),
            Self::PayloadDigestMismatch(root) => {
                write!(f, "belief payload digest mismatch: {root}")
            }
            Self::DerivationMismatch => f.write_str("independent belief derivation differs"),
        }
    }
}

impl std::error::Error for BeliefVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Read { cause, .. } => Some(cause),
            _ => None,
        }
    }
}

impl From<ContractError> for BeliefVerificationError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

/// An independently rebuilt belief pinned to an immutably borrowed authority ledger.
///
/// This is intentionally not canonically decodable: serialized belief bytes are not a proof of
/// current retention or a successful independent derivation. The ledger cannot advance through
/// this borrow while the verified projection is being produced.
#[derive(Debug)]
pub struct VerifiedDerivedBelief<'a> {
    belief: DerivedBelief,
    ledger: &'a ReferenceLedger,
}

impl VerifiedDerivedBelief<'_> {
    /// The independently rebuilt, still cognition-plane belief.
    #[must_use]
    pub const fn belief(&self) -> &DerivedBelief {
        &self.belief
    }

    /// Projects only against the authority anchor used for verification; never grants effects.
    pub fn to_knowledge_cell(&self) -> Result<KnowledgeCell, ContractError> {
        self.belief.to_knowledge_cell(&self.ledger.current().anchor)
    }
}

/// Verifies current-anchor membership, custody, bytes and an independent complete re-derivation.
///
/// Only direct authority payloads are admitted. Child-root reachability, cognition-plane outputs,
/// historical snapshots and BLAKE3 payloads need their own verified adapters; they are not silently
/// treated as verified here. All roots (including contradictions) are resolved before the engine
/// runs. A forged statement with a recomputed receipt still fails the complete result comparison.
pub fn verify_derived_belief<'a>(
    offered: &DerivedBelief,
    ledger: &'a ReferenceLedger,
    reader: &'a (impl RetainedBeliefEvidence + ?Sized),
    engine: &'a (impl RegisteredBeliefDeriver + ?Sized),
    limits: BeliefVerificationLimits,
) -> Result<VerifiedDerivedBelief<'a>, BeliefVerificationError> {
    offered.validate()?;
    let snapshot = ledger.current();
    offered.validate_anchor_freshness(&snapshot.anchor)?;
    if offered.derivation_inputs().algorithm_id != engine.algorithm_id() {
        return Err(BeliefVerificationError::AlgorithmMismatch);
    }
    if offered.generation() != engine.generation() {
        return Err(BeliefVerificationError::GenerationMismatch);
    }
    let root_count = offered.supporting_evidence().len() + offered.contradictions().len();
    if root_count > limits.max_roots {
        return Err(BeliefVerificationError::RootLimit);
    }
    if snapshot.objects.len() > limits.max_snapshot_objects {
        return Err(BeliefVerificationError::SnapshotLimit);
    }
    let wanted: BTreeSet<_> = offered
        .supporting_evidence()
        .iter()
        .chain(offered.contradictions())
        .copied()
        .collect();
    let mut bindings: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for (id, revision) in &snapshot.objects {
        if revision.plane == Plane::Authority && wanted.contains(&revision.payload_digest) {
            bindings
                .entry(revision.payload_digest)
                .or_default()
                .push((id.clone(), revision.clone()));
        }
    }
    // Check *all* memberships before reading anything, including contradicting roots.
    for root in &wanted {
        if !bindings.contains_key(root) {
            return Err(BeliefVerificationError::RootNotAnchored(*root));
        }
    }
    let mut remaining = limits.max_total_bytes;
    let mut read_roots = |roots: &[ContentDigest]| {
        let mut verified = Vec::with_capacity(roots.len());
        for root in roots {
            let allowance = limits.max_root_bytes.min(remaining);
            let bytes = reader
                .read_belief_evidence(*root, allowance)
                .map_err(|cause| BeliefVerificationError::Read {
                    digest: *root,
                    cause,
                })?;
            if bytes.len() > allowance {
                return Err(BeliefVerificationError::Read {
                    digest: *root,
                    cause: BeliefEvidenceReadError::LimitExceeded,
                });
            }
            // Comparing the whole digest also refuses algorithm aliases and laboratory roots.
            if ContentDigest::sha256(&bytes) != *root {
                return Err(BeliefVerificationError::PayloadDigestMismatch(*root));
            }
            remaining -= bytes.len();
            let root_bindings = bindings
                .remove(root)
                .ok_or(BeliefVerificationError::RootNotAnchored(*root))?;
            verified.push(VerifiedBeliefEvidence {
                digest: *root,
                bytes,
                bindings: root_bindings,
                ancestry: Vec::new(),
            });
        }
        Ok::<_, BeliefVerificationError>(verified)
    };
    let supporting = read_roots(offered.supporting_evidence())?;
    let contradicting = read_roots(offered.contradictions())?;
    let rebuilt = engine.derive(&BeliefRebuildInputs {
        belief_id: offered.belief_id(),
        anchor: &snapshot.anchor,
        supporting: &supporting,
        contradicting: &contradicting,
    })?;
    rebuilt.validate()?;
    if rebuilt != *offered {
        return Err(BeliefVerificationError::DerivationMismatch);
    }
    Ok(VerifiedDerivedBelief {
        belief: rebuilt,
        ledger,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    use crate::{
        BatchId, BeliefInterval, CaptureInterval, DerivedBeliefParams, DigestAlgorithm,
        EvidenceDelta, KnowledgeState, ProvenanceClass, TimestampNs,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[derive(Default)]
    struct Store {
        objects: BTreeMap<ContentDigest, Vec<u8>>,
        calls: Cell<usize>,
    }

    impl RetainedBeliefEvidence for Store {
        fn read_belief_evidence(
            &self,
            root: ContentDigest,
            _max_bytes: usize,
        ) -> Result<Vec<u8>, BeliefEvidenceReadError> {
            self.calls.set(self.calls.get() + 1);
            // Intentionally does not enforce the allowance: tests exercise the verifier too.
            self.objects
                .get(&root)
                .cloned()
                .ok_or(BeliefEvidenceReadError::Missing)
        }
    }

    struct SumEngine;

    impl RegisteredBeliefDeriver for SumEngine {
        fn algorithm_id(&self) -> &str {
            "alg:fixture-sum:v1"
        }
        fn generation(&self) -> Generation {
            Generation(7)
        }
        fn derive(&self, input: &BeliefRebuildInputs<'_>) -> Result<DerivedBelief, ContractError> {
            let sum = |roots: &[VerifiedBeliefEvidence]| -> usize {
                roots
                    .iter()
                    .flat_map(|root| root.bytes())
                    .map(|byte| usize::from(*byte))
                    .sum()
            };
            make_belief(
                input.anchor,
                &format!(
                    "sum {} minus {}",
                    sum(input.supporting),
                    sum(input.contradicting)
                ),
                input
                    .supporting
                    .iter()
                    .map(VerifiedBeliefEvidence::digest)
                    .collect(),
                input
                    .contradicting
                    .iter()
                    .map(VerifiedBeliefEvidence::digest)
                    .collect(),
            )
        }
    }

    fn make_belief(
        anchor: &LedgerAnchor,
        statement: &str,
        supporting_evidence: Vec<ContentDigest>,
        contradictions: Vec<ContentDigest>,
    ) -> Result<DerivedBelief, ContractError> {
        DerivedBelief::new(
            DerivedBeliefParams {
                belief_id: "belief:verified:001".to_owned(),
                anchor: anchor.clone(),
                generation: Generation(7),
                algorithm_id: "alg:fixture-sum:v1".to_owned(),
                statement: statement.to_owned(),
                knowledge_state: KnowledgeState::Estimated,
                provenance: ProvenanceClass::Derived,
                uncertainty: BeliefInterval::new(200_000, 800_000)?,
                supporting_evidence,
                contradictions,
                derivation_receipt: ContentDigest::sha256(b"unsealed"),
            }
            .with_computed_receipt()?,
        )
    }

    fn fixture(plane: Plane) -> Result<(ReferenceLedger, Store, DerivedBelief), ContractError> {
        let mut ledger = ReferenceLedger::new("site:verified");
        let mut store = Store::default();
        let mut deltas = Vec::new();
        for (i, bytes) in [vec![3], vec![1]].into_iter().enumerate() {
            let root = ContentDigest::sha256(&bytes);
            store.objects.insert(root, bytes);
            deltas.push(EvidenceDelta {
                delta_id: format!("delta:{i}"),
                family: "fixture_fact".to_owned(),
                object_id: ObjectId::parse(format!("object:{i}"))?,
                prior_generation: None,
                new_generation: 1,
                validity: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
                plane,
                payload_digest: root,
                witness_digest: None,
                operation_id: None,
            });
        }
        let batch = ledger.prepare_batch(BatchId::parse("batch:verified")?, deltas, [])?;
        let _ = ledger.append(batch)?;
        let belief = make_belief(
            &ledger.current().anchor,
            "sum 3 minus 1",
            vec![ContentDigest::sha256(&[3])],
            vec![ContentDigest::sha256(&[1])],
        )?;
        Ok((ledger, store, belief))
    }

    fn verify<'a>(
        belief: &DerivedBelief,
        ledger: &'a ReferenceLedger,
        store: &'a Store,
    ) -> Result<VerifiedDerivedBelief<'a>, BeliefVerificationError> {
        verify_derived_belief(
            belief,
            ledger,
            store,
            &SumEngine,
            BeliefVerificationLimits::default(),
        )
    }

    #[test]
    fn retained_authority_bytes_are_rederived_before_projection() -> TestResult {
        let (ledger, store, offered) = fixture(Plane::Authority)?;
        let verified = verify(&offered, &ledger, &store)?;
        assert_eq!(verified.belief(), &offered);
        assert_eq!(store.calls.get(), 2);
        let cell = verified.to_knowledge_cell()?;
        assert!(!cell.is_irreversible_effect_premise(TimestampNs(20)));
        Ok(())
    }

    #[test]
    fn recomputed_receipt_cannot_launder_a_fabricated_root() -> TestResult {
        let (ledger, store, _) = fixture(Plane::Authority)?;
        let root = ContentDigest::sha256(b"fabricated");
        let offered = make_belief(&ledger.current().anchor, "fabricated", vec![root], vec![])?;
        assert!(offered.rebuild().is_ok());
        assert_eq!(
            verify(&offered, &ledger, &store).err(),
            Some(BeliefVerificationError::RootNotAnchored(root))
        );
        assert_eq!(store.calls.get(), 0);
        Ok(())
    }

    #[test]
    fn a_valid_receipt_and_real_roots_do_not_prove_the_statement() -> TestResult {
        let (ledger, store, _) = fixture(Plane::Authority)?;
        let offered = make_belief(
            &ledger.current().anchor,
            "fabricated conclusion",
            vec![ContentDigest::sha256(&[3])],
            vec![ContentDigest::sha256(&[1])],
        )?;
        assert!(offered.rebuild().is_ok());
        assert_eq!(
            verify(&offered, &ledger, &store).err(),
            Some(BeliefVerificationError::DerivationMismatch)
        );
        Ok(())
    }

    #[test]
    fn missing_and_corrupt_contradicting_bytes_are_not_silently_dropped() -> TestResult {
        let (ledger, mut store, offered) = fixture(Plane::Authority)?;
        let root = offered.contradictions()[0];
        store.objects.remove(&root);
        assert_eq!(
            verify(&offered, &ledger, &store).err(),
            Some(BeliefVerificationError::Read {
                digest: root,
                cause: BeliefEvidenceReadError::Missing,
            })
        );
        store.objects.insert(root, vec![9]);
        assert_eq!(
            verify(&offered, &ledger, &store).err(),
            Some(BeliefVerificationError::PayloadDigestMismatch(root))
        );
        Ok(())
    }

    #[test]
    fn retained_but_unanchored_or_cognition_only_roots_are_refused() -> TestResult {
        let (ledger, mut store, offered) = fixture(Plane::Cognition)?;
        assert!(matches!(
            verify(&offered, &ledger, &store),
            Err(BeliefVerificationError::RootNotAnchored(_))
        ));
        let root = ContentDigest::sha256(b"retained but unanchored");
        store
            .objects
            .insert(root, b"retained but unanchored".to_vec());
        let offered = make_belief(&ledger.current().anchor, "unanchored", vec![root], vec![])?;
        assert_eq!(
            verify(&offered, &ledger, &store).err(),
            Some(BeliefVerificationError::RootNotAnchored(root))
        );
        assert_eq!(store.calls.get(), 0);
        Ok(())
    }

    #[test]
    fn stale_and_forked_claims_fail_before_any_custody_read() -> TestResult {
        let (mut ledger, store, offered) = fixture(Plane::Authority)?;
        let mut anchor = offered.anchor().clone();
        anchor.privacy_epoch += 1;
        let forked = make_belief(
            &anchor,
            offered.statement(),
            offered.supporting_evidence().to_vec(),
            offered.contradictions().to_vec(),
        )?;
        assert_eq!(
            verify(&forked, &ledger, &store).err(),
            Some(BeliefVerificationError::Contract(
                ContractError::DerivedBeliefAnchorMismatch,
            ))
        );
        let batch = ledger.prepare_batch(BatchId::parse("batch:advance")?, vec![], [])?;
        let _ = ledger.append(batch)?;
        assert_eq!(
            verify(&offered, &ledger, &store).err(),
            Some(BeliefVerificationError::Contract(
                ContractError::StaleAnchor
            ))
        );
        assert_eq!(store.calls.get(), 0);
        Ok(())
    }

    #[test]
    fn root_and_snapshot_budgets_are_checked_before_io() -> TestResult {
        let (ledger, store, offered) = fixture(Plane::Authority)?;
        for (limits, error) in [
            (
                BeliefVerificationLimits {
                    max_roots: 1,
                    ..Default::default()
                },
                BeliefVerificationError::RootLimit,
            ),
            (
                BeliefVerificationLimits {
                    max_snapshot_objects: 1,
                    ..Default::default()
                },
                BeliefVerificationError::SnapshotLimit,
            ),
        ] {
            assert_eq!(
                verify_derived_belief(&offered, &ledger, &store, &SumEngine, limits).err(),
                Some(error)
            );
        }
        assert_eq!(store.calls.get(), 0);
        Ok(())
    }

    #[test]
    fn aggregate_and_per_root_limits_cannot_be_bypassed_by_the_reader() -> TestResult {
        let (ledger, store, offered) = fixture(Plane::Authority)?;
        for limits in [
            BeliefVerificationLimits {
                max_total_bytes: 1,
                ..Default::default()
            },
            BeliefVerificationLimits {
                max_root_bytes: 0,
                ..Default::default()
            },
        ] {
            assert!(matches!(
                verify_derived_belief(&offered, &ledger, &store, &SumEngine, limits),
                Err(BeliefVerificationError::Read {
                    cause: BeliefEvidenceReadError::LimitExceeded,
                    ..
                })
            ));
        }
        let limits = BeliefVerificationLimits {
            max_total_bytes: 2,
            max_root_bytes: 1,
            ..Default::default()
        };
        assert!(verify_derived_belief(&offered, &ledger, &store, &SumEngine, limits).is_ok());
        Ok(())
    }

    #[test]
    fn algorithm_qualified_roots_are_not_hash_byte_aliases() -> TestResult {
        let (ledger, store, _) = fixture(Plane::Authority)?;
        let sha = ContentDigest::sha256(&[3]);
        let alias = ContentDigest::new(DigestAlgorithm::Blake3, sha.bytes());
        let offered = make_belief(&ledger.current().anchor, "alias", vec![alias], vec![])?;
        assert_eq!(
            verify(&offered, &ledger, &store).err(),
            Some(BeliefVerificationError::RootNotAnchored(alias))
        );
        assert_eq!(store.calls.get(), 0);
        Ok(())
    }
}
