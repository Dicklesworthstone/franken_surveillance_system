#![forbid(unsafe_code)]
//! Deletion-owner bridge for durable retained-belief verification.
//!
//! This module turns committed deletion authority into native custody denials. It reuses the
//! canonical deletion proof reader; it never infers deletion from missing files, repairs history,
//! or grants read authority. A committed header denies its complete closure before unlinking.

mod bounded;
pub use bounded::{
    BoundedCommittedDeletionBeliefAuthority, DeletionBeliefLimits, DeletionBeliefUsage,
};
/// Deployment-backed H3 disclosure honoring committed deletion and exact slot authority.
pub mod hydration;

use std::collections::BTreeMap;

use fss_core::ContentDigest;
use fss_core::belief_verification::RegisteredBeliefDeriver;
use fss_ledger::DurableReferenceLedger;
use fss_object::SpoolIo;
use fss_publication::{LocalRootPublisher, SlotName};
use fss_publication::custody_audit::belief_snapshot::durable::{
    DurableBeliefDeletionAuthority, DurableBeliefError, DurableBeliefRequest,
    VerifiedDurableBelief, verify_durable_belief_with_deletion_authority,
};

use crate::ReferenceDeployment;

/// Compatibility entry point using default, per-call deletion-proof admission.
///
/// Authority comes from the implementation, not a serialized token. For cancellation and retained
/// failure accounting, use a request-owned [`BoundedCommittedDeletionBeliefAuthority`] instead.
#[derive(Clone, Copy, Debug, Default)]
pub struct CommittedDeletionBeliefAuthority;

impl DurableBeliefDeletionAuthority for CommittedDeletionBeliefAuthority {
    fn verified_denials(
        &self,
        ledger: &DurableReferenceLedger,
        publisher: &LocalRootPublisher,
    ) -> Result<BTreeMap<ContentDigest, ContentDigest>, DurableBeliefError> {
        BoundedCommittedDeletionBeliefAuthority::new(DeletionBeliefLimits::default(), &|| false)
            .verified_denials(ledger, publisher)
    }

    fn verified_denials_for_slots(
        &self,
        ledger: &DurableReferenceLedger,
        publisher: &LocalRootPublisher,
        slots: &[SlotName],
    ) -> Result<BTreeMap<ContentDigest, ContentDigest>, DurableBeliefError> {
        BoundedCommittedDeletionBeliefAuthority::new(DeletionBeliefLimits::default(), &|| false)
            .verified_denials_for_slots(ledger, publisher, slots)
    }
}

/// Verify a saved belief against an opened reference deployment while honoring committed deletion
/// authority, with default deletion-history limits and the request's cancellation owner.
///
/// Every deleted object is added to the native deny set before selected payload custody is copied;
/// explicit request denials only narrow it. Committed slot retractions are checked independently
/// of object deletion, so shared retained bytes cannot revive a revoked slot. Unrelated intact
/// slots may remain verifiable after another closure was deleted. This wrapper neither
/// authenticates callers nor applies privacy policy on their behalf. Each call is a fresh admission.
/// To retain deletion work across refusals, explicitly construct a bounded authority and use the
/// publication-layer entry point with it.
pub fn verify_durable_belief_with_committed_deletions<'a, C: Fn() -> bool + Sync>(
    encoded: &[u8],
    deployment: &'a ReferenceDeployment,
    io: &dyn SpoolIo,
    engine: &(impl RegisteredBeliefDeriver + ?Sized),
    request: DurableBeliefRequest<'_, C>,
) -> Result<VerifiedDurableBelief<'a>, DurableBeliefError> {
    let authority = BoundedCommittedDeletionBeliefAuthority::new(
        DeletionBeliefLimits::default(),
        request.cancelled,
    );
    verify_durable_belief_with_deletion_authority(
        encoded,
        deployment.ledger(),
        deployment.publisher(),
        io,
        engine,
        &authority,
        request,
    )
}
