#![forbid(unsafe_code)]
//! Deletion-owner bridge for durable retained-belief verification.
//!
//! This module is the only reference-layer adapter that turns committed deletion authority into
//! native custody denials. It reuses the canonical deletion proof reader; it never infers deletion
//! from missing files, never repairs history, and never grants read authority.

use std::collections::BTreeMap;

use fss_core::ContentDigest;
use fss_core::belief_verification::RegisteredBeliefDeriver;
use fss_ledger::DurableReferenceLedger;
use fss_object::SpoolIo;
use fss_publication::LocalRootPublisher;
use fss_publication::custody_audit::belief_snapshot::durable::{
    DurableBeliefDeletionAuthority, DurableBeliefError, DurableBeliefRequest,
    VerifiedDurableBelief, verify_durable_belief_with_deletion_authority,
};

use super::{DeletionError, DeletionIndex, has_records};
use crate::ReferenceDeployment;

/// Trusted reference deletion owner.
///
/// Construction is intentionally trivial: authority comes from the implementation, not a token
/// supplied by serialized input. The implementation validates the complete deletion transition
/// history against retained plan/completion bytes every time it is asked for denials.
#[derive(Clone, Copy, Debug, Default)]
pub struct CommittedDeletionBeliefAuthority;

impl DurableBeliefDeletionAuthority for CommittedDeletionBeliefAuthority {
    fn verified_denials(
        &self,
        ledger: &DurableReferenceLedger,
        publisher: &LocalRootPublisher,
    ) -> Result<BTreeMap<ContentDigest, ContentDigest>, DurableBeliefError> {
        if !has_records(ledger.batches()) {
            return Ok(BTreeMap::new());
        }
        let index: DeletionIndex = DeletionIndex::from_batches(ledger.batches(), |digest| {
            publisher
                .spool()
                .read(digest)
                .map(|bytes| bytes.to_vec())
                .map_err(DeletionError::from)
        })
        .map_err(|_: DeletionError| DurableBeliefError::DeletionAuthorityInvalid)?;

        let mut denied = BTreeMap::new();
        for entry in index.entries() {
            for object in &entry.plan.deletable {
                if let Some(previous) = denied.insert(object.digest, entry.plan_digest)
                    && previous != entry.plan_digest
                {
                    // One object cannot have two different canonical deletion authorities in the
                    // same verified history without an explicit supersession contract.
                    return Err(DurableBeliefError::DeletionAuthorityInvalid);
                }
            }
        }
        Ok(denied)
    }
}

/// Verify a saved belief against an opened reference deployment while honoring committed deletion
/// authority.
///
/// The deployment's deletion history is validated before selected payload custody is copied. Every
/// deleted object is added to the native deny set; explicit request denials can only narrow it.
/// Unrelated, intact selected slots may therefore remain verifiable after another evidence closure
/// was deleted. This wrapper does not authenticate the caller or apply privacy policy on its behalf.
pub fn verify_durable_belief_with_committed_deletions<'a, C: Fn() -> bool + Sync>(
    encoded: &[u8],
    deployment: &'a ReferenceDeployment,
    io: &dyn SpoolIo,
    engine: &(impl RegisteredBeliefDeriver + ?Sized),
    request: DurableBeliefRequest<'_, C>,
) -> Result<VerifiedDurableBelief<'a>, DurableBeliefError> {
    verify_durable_belief_with_deletion_authority(
        encoded,
        deployment.ledger(),
        deployment.publisher(),
        io,
        engine,
        &CommittedDeletionBeliefAuthority,
        request,
    )
}
