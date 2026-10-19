//! Retained-object custody and bounded canonical intake for derived beliefs.
//!
//! Decoding an intact receipt is not provenance verification. This module connects the core
//! verifier to the existing object store and admits canonical belief bytes only after current
//! authority membership, retained-byte integrity, and independent derivation all succeed.
//! It performs no publication, repairs, device I/O, or effect authorization.

use std::fmt;

use fss_core::belief_verification::{
    BeliefEvidenceReadError, BeliefVerificationError, BeliefVerificationLimits,
    RegisteredBeliefDeriver, RetainedBeliefEvidence, VerifiedDerivedBelief, verify_derived_belief,
};
use fss_core::{CanonicalDecode, ContentDigest, ContractError, DerivedBelief, ReferenceLedger};

use crate::{InMemoryObjectStore, ObjectError};

impl RetainedBeliefEvidence for InMemoryObjectStore {
    fn read_belief_evidence(
        &self,
        digest: ContentDigest,
        max_bytes: usize,
    ) -> Result<Vec<u8>, BeliefEvidenceReadError> {
        // Use the existing custody gate: reading must never promote a staged object to verified.
        let bytes = self.read_verified(digest).map_err(|error| match error {
            ObjectError::Missing(_) | ObjectError::Tombstoned(_) => {
                BeliefEvidenceReadError::Missing
            }
            ObjectError::NotVerified(_) => BeliefEvidenceReadError::NotVerified,
            ObjectError::Corrupt(_) => BeliefEvidenceReadError::Corrupt,
            _ => BeliefEvidenceReadError::Unavailable,
        })?;
        // Enforce the caller's allowance before allocating the owned evidence copy. The store
        // independently bounds and rehashes its existing resident payload during read_verified.
        if bytes.len() > max_bytes {
            return Err(BeliefEvidenceReadError::LimitExceeded);
        }
        Ok(bytes.to_vec())
    }
}

/// Bounds for decoding and verifying one offered canonical belief.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedBeliefIntakeLimits {
    /// Maximum encoded input length, checked before any canonical decoding allocation.
    pub max_encoded_bytes: usize,
    /// Authority-membership and retained-payload limits for the core verifier.
    pub verification: BeliefVerificationLimits,
}

impl Default for RetainedBeliefIntakeLimits {
    fn default() -> Self {
        Self {
            max_encoded_bytes: 256 * 1024,
            verification: BeliefVerificationLimits::default(),
        }
    }
}

/// An intact input can still fail retention or provenance verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetainedBeliefIntakeError {
    /// The input exceeds the decoding allowance.
    EncodedLimit {
        /// Actual encoded length.
        length: usize,
        /// Configured maximum encoded length.
        maximum: usize,
    },
    /// Malformed, truncated, noncanonical, or trailing input bytes.
    Decode(ContractError),
    /// Freshness, membership, custody, registration, or independent derivation failed.
    Verification(BeliefVerificationError),
}

impl fmt::Display for RetainedBeliefIntakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncodedLimit { length, maximum } => {
                write!(
                    f,
                    "encoded belief length {length} exceeds allowance {maximum}"
                )
            }
            Self::Decode(error) => write!(f, "belief decode: {error}"),
            Self::Verification(error) => write!(f, "belief verification: {error}"),
        }
    }
}

impl std::error::Error for RetainedBeliefIntakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            Self::Verification(error) => Some(error),
            Self::EncodedLimit { .. } => None,
        }
    }
}

/// Admits complete canonical bytes only through current retained-evidence verification.
///
/// The ledger, store and registered engine must be independently selected trusted inputs, not
/// constructed from the offered claim. This checks the entire encoding (including end-of-input),
/// re-reads custody-verified authority payloads, and independently rebuilds the result. A decoded
/// `DerivedBelief` never leaves this boundary on its own. The returned proof borrows the trusted
/// inputs and cannot be restored by simply decoding a saved receipt.
///
/// This reference adapter intentionally admits only direct current authority payloads supported
/// by the core verifier; it makes no transitive-manifest or production-engine registry claim.
pub fn decode_and_verify_retained_belief<'a>(
    encoded: &[u8],
    ledger: &'a ReferenceLedger,
    store: &'a InMemoryObjectStore,
    engine: &'a (impl RegisteredBeliefDeriver + ?Sized),
    limits: RetainedBeliefIntakeLimits,
) -> Result<VerifiedDerivedBelief<'a>, RetainedBeliefIntakeError> {
    if encoded.len() > limits.max_encoded_bytes {
        return Err(RetainedBeliefIntakeError::EncodedLimit {
            length: encoded.len(),
            maximum: limits.max_encoded_bytes,
        });
    }
    let offered =
        DerivedBelief::from_canonical_bytes(encoded).map_err(RetainedBeliefIntakeError::Decode)?;
    verify_derived_belief(&offered, ledger, store, engine, limits.verification)
        .map_err(RetainedBeliefIntakeError::Verification)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    use fss_core::belief_verification::BeliefRebuildInputs;
    use fss_core::{
        BatchId, BeliefInterval, CanonicalEncode, CaptureInterval, DerivedBeliefParams,
        EvidenceDelta, Generation, KnowledgeState, LedgerAnchor, ObjectId, Plane, ProvenanceClass,
        TimestampNs,
    };

    use crate::{ObjectLimits, ObjectState};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    struct ByteEngine {
        calls: Cell<usize>,
        algorithm: &'static str,
        generation: Generation,
    }

    impl Default for ByteEngine {
        fn default() -> Self {
            Self {
                calls: Cell::new(0),
                algorithm: "alg:fixture-byte:v1",
                generation: Generation(1),
            }
        }
    }

    impl RegisteredBeliefDeriver for ByteEngine {
        fn algorithm_id(&self) -> &str {
            self.algorithm
        }

        fn generation(&self) -> Generation {
            self.generation
        }

        fn derive(&self, inputs: &BeliefRebuildInputs<'_>) -> Result<DerivedBelief, ContractError> {
            self.calls.set(self.calls.get() + 1);
            let [evidence] = inputs.supporting else {
                return Err(ContractError::EvidenceRequired);
            };
            if inputs.belief_id != "belief:retained-byte"
                || !inputs.contradicting.is_empty()
                || evidence.bytes() != [42]
                || evidence.bindings().len() != 1
                || evidence.bindings()[0].1.family != "fixture_byte"
            {
                return Err(ContractError::EvidenceRequired);
            }
            belief(
                inputs.anchor,
                evidence.digest(),
                "retained byte is 42",
                800_000,
            )
        }
    }

    fn belief(
        anchor: &LedgerAnchor,
        root: ContentDigest,
        statement: &str,
        upper: u64,
    ) -> Result<DerivedBelief, ContractError> {
        DerivedBelief::new(
            DerivedBeliefParams {
                belief_id: "belief:retained-byte".to_owned(),
                anchor: anchor.clone(),
                generation: Generation(1),
                algorithm_id: "alg:fixture-byte:v1".to_owned(),
                statement: statement.to_owned(),
                knowledge_state: KnowledgeState::Estimated,
                provenance: ProvenanceClass::Derived,
                uncertainty: BeliefInterval::new(200_000, upper)?,
                supporting_evidence: vec![root],
                contradictions: vec![],
                derivation_receipt: ContentDigest::sha256(b"unsealed"),
            }
            .with_computed_receipt()?,
        )
    }

    fn fixture()
    -> Result<(ReferenceLedger, InMemoryObjectStore, DerivedBelief), Box<dyn std::error::Error>>
    {
        let mut store = InMemoryObjectStore::new(ObjectLimits::default());
        let root = store.put_verified(&[42])?;
        let mut ledger = ReferenceLedger::new("site:retained-byte");
        let batch = ledger.prepare_batch(
            BatchId::parse("batch:retained-byte")?,
            vec![EvidenceDelta {
                delta_id: "delta:retained-byte".to_owned(),
                family: "fixture_byte".to_owned(),
                object_id: ObjectId::parse("object:retained-byte")?,
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
        let offered = belief(
            &ledger.current().anchor,
            root,
            "retained byte is 42",
            800_000,
        )?;
        Ok((ledger, store, offered))
    }

    fn intake<'a>(
        bytes: &[u8],
        ledger: &'a ReferenceLedger,
        store: &'a InMemoryObjectStore,
        engine: &'a ByteEngine,
    ) -> Result<VerifiedDerivedBelief<'a>, RetainedBeliefIntakeError> {
        decode_and_verify_retained_belief(
            bytes,
            ledger,
            store,
            engine,
            RetainedBeliefIntakeLimits::default(),
        )
    }

    #[test]
    fn canonical_intake_uses_real_custody_without_mutating_the_store_or_ledger() -> TestResult {
        let (ledger, store, offered) = fixture()?;
        let before = (
            store.object_count(),
            store.total_bytes(),
            ledger.batches().len(),
        );
        let bytes = offered.try_canonical_bytes()?;
        let engine = ByteEngine::default();
        let proof = intake(&bytes, &ledger, &store, &engine)?;
        assert_eq!(proof.belief(), &offered);
        assert_eq!(engine.calls.get(), 1);
        assert!(
            !proof
                .to_knowledge_cell()?
                .is_irreversible_effect_premise(TimestampNs(20))
        );
        assert_eq!(
            before,
            (
                store.object_count(),
                store.total_bytes(),
                ledger.batches().len()
            )
        );
        assert_eq!(
            store.state(offered.supporting_evidence()[0]),
            Some(ObjectState::Verified)
        );
        Ok(())
    }

    #[test]
    fn staged_bytes_never_become_verified_as_a_side_effect_of_intake() -> TestResult {
        let (ledger, _, offered) = fixture()?;
        let mut store = InMemoryObjectStore::new(ObjectLimits::default());
        let root = store.stage(&[42])?;
        let bytes = offered.try_canonical_bytes()?;
        let engine = ByteEngine::default();
        assert_eq!(
            intake(&bytes, &ledger, &store, &engine).err(),
            Some(RetainedBeliefIntakeError::Verification(
                BeliefVerificationError::Read {
                    digest: root,
                    cause: BeliefEvidenceReadError::NotVerified,
                }
            ))
        );
        assert_eq!(store.state(root), Some(ObjectState::Staged));
        assert_eq!(engine.calls.get(), 0);
        Ok(())
    }

    #[test]
    fn anchored_but_missing_or_corrupted_payloads_are_refused_before_derivation() -> TestResult {
        let (ledger, mut store, offered) = fixture()?;
        let empty = InMemoryObjectStore::new(ObjectLimits::default());
        let root = offered.supporting_evidence()[0];
        let bytes = offered.try_canonical_bytes()?;
        let engine = ByteEngine::default();
        assert_eq!(
            intake(&bytes, &ledger, &empty, &engine).err(),
            Some(RetainedBeliefIntakeError::Verification(
                BeliefVerificationError::Read {
                    digest: root,
                    cause: BeliefEvidenceReadError::Missing,
                }
            ))
        );
        store.corrupt_for_test(root)?;
        assert_eq!(
            intake(&bytes, &ledger, &store, &engine).err(),
            Some(RetainedBeliefIntakeError::Verification(
                BeliefVerificationError::Read {
                    digest: root,
                    cause: BeliefEvidenceReadError::Corrupt,
                }
            ))
        );
        assert_eq!(engine.calls.get(), 0);
        Ok(())
    }

    #[test]
    fn encoded_length_limit_precedes_decode_and_accepts_the_exact_boundary() -> TestResult {
        let (ledger, store, offered) = fixture()?;
        let bytes = offered.try_canonical_bytes()?;
        let engine = ByteEngine::default();
        let mut limits = RetainedBeliefIntakeLimits {
            max_encoded_bytes: bytes.len() - 1,
            ..Default::default()
        };
        assert_eq!(
            decode_and_verify_retained_belief(&bytes, &ledger, &store, &engine, limits).err(),
            Some(RetainedBeliefIntakeError::EncodedLimit {
                length: bytes.len(),
                maximum: bytes.len() - 1,
            })
        );
        assert_eq!(engine.calls.get(), 0);
        limits.max_encoded_bytes = bytes.len();
        assert!(
            decode_and_verify_retained_belief(&bytes, &ledger, &store, &engine, limits).is_ok()
        );
        assert_eq!(engine.calls.get(), 1);
        Ok(())
    }

    #[test]
    fn trailing_bytes_and_every_truncated_prefix_fail_before_derivation() -> TestResult {
        let (ledger, store, offered) = fixture()?;
        let bytes = offered.try_canonical_bytes()?;
        let engine = ByteEngine::default();
        for length in 0..bytes.len() {
            assert!(
                matches!(
                    intake(&bytes[..length], &ledger, &store, &engine),
                    Err(RetainedBeliefIntakeError::Decode(_))
                ),
                "accepted truncated prefix length {length}"
            );
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(matches!(
            intake(&trailing, &ledger, &store, &engine),
            Err(RetainedBeliefIntakeError::Decode(_))
        ));
        assert_eq!(engine.calls.get(), 0);
        Ok(())
    }

    #[test]
    fn independent_registration_not_the_claim_selects_algorithm_and_generation() -> TestResult {
        let (ledger, store, offered) = fixture()?;
        let bytes = offered.try_canonical_bytes()?;
        for (engine, failure) in [
            (
                ByteEngine {
                    algorithm: "alg:other:v1",
                    ..Default::default()
                },
                BeliefVerificationError::AlgorithmMismatch,
            ),
            (
                ByteEngine {
                    generation: Generation(2),
                    ..Default::default()
                },
                BeliefVerificationError::GenerationMismatch,
            ),
        ] {
            assert_eq!(
                intake(&bytes, &ledger, &store, &engine).err(),
                Some(RetainedBeliefIntakeError::Verification(failure))
            );
            assert_eq!(engine.calls.get(), 0);
        }
        Ok(())
    }

    #[test]
    fn a_resealed_fabricated_statement_or_confidence_does_not_pass_intake() -> TestResult {
        let (ledger, store, offered) = fixture()?;
        let root = offered.supporting_evidence()[0];
        let engine = ByteEngine::default();
        for forged in [
            belief(offered.anchor(), root, "fabricated conclusion", 800_000)?,
            belief(offered.anchor(), root, offered.statement(), 1_000_000)?,
        ] {
            assert!(forged.rebuild().is_ok());
            assert_eq!(
                intake(&forged.try_canonical_bytes()?, &ledger, &store, &engine).err(),
                Some(RetainedBeliefIntakeError::Verification(
                    BeliefVerificationError::DerivationMismatch
                ))
            );
        }
        assert_eq!(engine.calls.get(), 2);
        Ok(())
    }

    #[test]
    fn cold_replay_requires_retained_bytes_and_rederives_instead_of_trusting_the_saved_receipt()
    -> TestResult {
        let (ledger, store, offered) = fixture()?;
        let root = offered.supporting_evidence()[0];
        let bytes = offered.try_canonical_bytes()?;
        let cold = ReferenceLedger::replay("site:retained-byte", ledger.batches().iter().cloned())?;
        let mut cold_store = InMemoryObjectStore::new(ObjectLimits::default());
        let engine = ByteEngine::default();
        assert_eq!(
            intake(&bytes, &cold, &cold_store, &engine).err(),
            Some(RetainedBeliefIntakeError::Verification(
                BeliefVerificationError::Read {
                    digest: root,
                    cause: BeliefEvidenceReadError::Missing,
                }
            ))
        );
        assert_eq!(cold_store.put_verified(store.read_verified(root)?)?, root);
        assert_eq!(
            intake(&bytes, &cold, &cold_store, &engine)?.belief(),
            &offered
        );
        assert_eq!(engine.calls.get(), 1);
        Ok(())
    }

    #[test]
    fn saved_belief_bytes_do_not_bypass_freshness_after_the_ledger_advances() -> TestResult {
        let (mut ledger, store, offered) = fixture()?;
        let bytes = offered.try_canonical_bytes()?;
        let batch = ledger.prepare_batch(BatchId::parse("batch:advance")?, vec![], [])?;
        let _ = ledger.append(batch)?;
        let engine = ByteEngine::default();
        assert_eq!(
            intake(&bytes, &ledger, &store, &engine).err(),
            Some(RetainedBeliefIntakeError::Verification(
                BeliefVerificationError::Contract(ContractError::StaleAnchor)
            ))
        );
        assert_eq!(engine.calls.get(), 0);
        Ok(())
    }

    #[test]
    fn custody_adapter_honors_exact_copy_budget_and_never_allocates_an_over_budget_copy()
    -> TestResult {
        let (_, store, offered) = fixture()?;
        let root = offered.supporting_evidence()[0];
        assert_eq!(
            store.read_belief_evidence(root, 0),
            Err(BeliefEvidenceReadError::LimitExceeded)
        );
        assert_eq!(store.read_belief_evidence(root, 1), Ok(vec![42]));
        assert_eq!(store.state(root), Some(ObjectState::Verified));
        Ok(())
    }
}
