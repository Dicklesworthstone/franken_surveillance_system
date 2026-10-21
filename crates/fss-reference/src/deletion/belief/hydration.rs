#![forbid(unsafe_code)]
//! H3 source disclosure under current durable and committed deletion authority.
//!
//! The ordinary hydration owner admits capability, privacy, retention, price and cursors before
//! invoking this reader. Publication alone cannot see a committed deletion header: this adapter
//! validates that header and its slot retractions before touching the selected source closure.

use std::cell::Cell;

use fss_core::belief_verification::{BeliefEvidenceReadError, RetainedBeliefEvidence};
use fss_core::{
    ContentDigest, HydrationError, HydrationRequest, HydrationResponse, LedgerAnchor, Plane,
    SemanticHandle, TimestampNs,
};
use fss_object::{ObjectError, SpoolIo};
use fss_publication::custody_audit::belief_snapshot::capture_belief_custody;
use fss_publication::custody_audit::belief_snapshot::durable::{
    DurableBeliefDeletionAuthority, DurableBeliefError,
};
use fss_publication::custody_audit::{CustodyAuditLimits, CustodyRootBasis};
use fss_publication::{
    LocalPublicationState, ROOT_REACHABILITY_FAMILY, SlotName, root_reachability_object_id,
};

use super::{
    BoundedCommittedDeletionBeliefAuthority, DeletionBeliefLimits, DeletionBeliefUsage,
};
use crate::hydration::{PublishedSourceReader, SourceObjectBinding};
use crate::{ReferenceDeployment, ReferenceHydrationCatalog, SourceHydrationError};

/// Independent allowances for one source disclosure. The descriptor's existing full-vector quote
/// controls its artifact; these ceilings additionally bound native verification of its closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeploymentSourceLimits {
    /// Canonical deletion-history validation, including failed-read reservations.
    pub deletion: DeletionBeliefLimits,
    /// One cumulative native catalogue, closure audit and capture allowance.
    pub custody: CustodyAuditLimits,
    /// Maximum retained closure payload bytes; excludes the final bounded subject copy.
    pub max_retained_bytes: u64,
}

impl Default for DeploymentSourceLimits {
    fn default() -> Self {
        Self {
            deletion: DeletionBeliefLimits::default(),
            custody: CustodyAuditLimits::default(),
            max_retained_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Completed capture cost, separate from the hydration receipt's quoted artifact cost and the
/// deletion owner's logical reservations. No complete capture is reported on capture failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceCustodyUsage {
    /// Charged native read bytes, including catalogue and envelope verification.
    pub charged_read_bytes: u64,
    /// Filesystem calls made by the capture's read-only capability.
    pub io_calls: u64,
    /// Owned payload bytes captured across the selected closure.
    pub retained_bytes: u64,
}

/// Single-attempt source reader borrowing the deployment's lock-owning durable owners.
///
/// Construction performs no I/O. The slot and expected anchor are independently selected by the
/// authority owner, never inferred from untrusted source bytes. Use a fresh reader for each bind
/// or disclosure; repeated calls cannot refill its allowances. The catalog retains no source copy.
/// A completed read proves an observation, not a future retention lease or physical absence.
///
/// This does not authenticate a principal or invent privacy grants. The ordinary hydration
/// validator must receive trusted, policy-projected grants. The owner must authorize verification
/// of the entire selected closure. Raw source cannot implement a mask or redaction transform.
/// Journal-head checks are bounded native checks, not a historical scrub.
pub struct DeletionAwareSourceReader<'a, C: Fn() -> bool + Sync> {
    deployment: &'a ReferenceDeployment,
    io: &'a dyn SpoolIo,
    slot: &'a SlotName,
    anchor: &'a LedgerAnchor,
    limits: DeploymentSourceLimits,
    cancelled: &'a C,
    deletion: BoundedCommittedDeletionBeliefAuthority<'a, C>,
    attempted: Cell<bool>,
    custody_usage: Cell<Option<SourceCustodyUsage>>,
}

impl<'a, C: Fn() -> bool + Sync> DeletionAwareSourceReader<'a, C> {
    /// Selects exact authority and allowances without reading storage or allocating source bytes.
    #[must_use]
    pub fn new(
        deployment: &'a ReferenceDeployment,
        io: &'a dyn SpoolIo,
        slot: &'a SlotName,
        anchor: &'a LedgerAnchor,
        limits: DeploymentSourceLimits,
        cancelled: &'a C,
    ) -> Self {
        Self {
            deployment,
            io,
            slot,
            anchor,
            limits,
            cancelled,
            deletion: BoundedCommittedDeletionBeliefAuthority::new(limits.deletion, cancelled),
            attempted: Cell::new(false),
            custody_usage: Cell::new(None),
        }
    }

    /// Whether a custody attempt started, including cancellation or refusal.
    #[must_use]
    pub fn attempted(&self) -> bool {
        self.attempted.get()
    }

    /// Deletion work remains visible even when a source read is refused.
    #[must_use]
    pub fn deletion_usage(&self) -> DeletionBeliefUsage {
        self.deletion.usage()
    }

    /// Completed capture work, retained even if a later head check rejects disclosure.
    /// A failed capture currently supplies no unified partial-I/O receipt.
    #[must_use]
    pub fn custody_usage(&self) -> Option<SourceCustodyUsage> {
        self.custody_usage.get()
    }

    fn checkpoint(&self) -> Result<(), DurableBeliefError> {
        if (self.cancelled)() {
            Err(DurableBeliefError::Cancelled)
        } else {
            Ok(())
        }
    }

    fn check_head(&self, pin: ContentDigest, head: ContentDigest) -> Result<(), DurableBeliefError> {
        self.checkpoint()?;
        let ledger = self.deployment.ledger();
        if ledger.store_pin() != Some(pin) || !ledger.store_pin_is_current() {
            return Err(DurableBeliefError::StoreIdentity);
        }
        ledger.verify_durable_head()?;
        self.checkpoint()?;
        if self.deployment.publisher().is_poisoned()
            || ledger.journal_root() != head
            || &ledger.current().anchor != self.anchor
        {
            return Err(DurableBeliefError::AuthorityChanged);
        }
        Ok(())
    }

    fn read(
        &self,
        root: ContentDigest,
        subject: ContentDigest,
        ceiling: u64,
    ) -> Result<Vec<u8>, SourceHydrationError> {
        if self.attempted.replace(true) {
            return Err(DurableBeliefError::Limit("source disclosure attempts").into());
        }
        self.checkpoint()?;
        let ledger = self.deployment.ledger();
        let publisher = self.deployment.publisher();
        let pin = ledger.store_pin().ok_or(DurableBeliefError::StoreIdentity)?;
        let head = ledger.journal_root();
        self.check_head(pin, head)?;

        // A header alone revokes its selected slots and denies its complete content closure.
        // Waiting for individual retraction deltas or unlinking would disclose deleted evidence.
        let denied = self.deletion.verified_denials_for_slots(
            ledger,
            publisher,
            std::slice::from_ref(self.slot),
        )?;
        self.check_head(pin, head)?;
        for digest in [root, subject] {
            if denied.contains_key(&digest) {
                return Err(ObjectError::Tombstoned(digest).into());
            }
        }
        let id = root_reachability_object_id(self.slot)
            .map_err(|_| DurableBeliefError::Selection)?;
        let revision = ledger.current().objects.get(&id).ok_or(DurableBeliefError::Selection)?;
        let local = publisher.root(self.slot).ok_or(DurableBeliefError::Selection)?;
        if revision.plane != Plane::Authority
            || revision.family != ROOT_REACHABILITY_FAMILY
            || revision.generation != 1
            || revision.payload_digest != root
            || local.root != root
            || local.state != LocalPublicationState::Durable
        {
            return Err(DurableBeliefError::Selection.into());
        }
        self.checkpoint()?;
        let custody = capture_belief_custody(
            self.io,
            publisher.root_dir(),
            &[root],
            &denied,
            self.limits.custody,
            self.cancelled,
            CustodyRootBasis::LocalPublicationRecords,
            self.limits.max_retained_bytes,
        )
        .map_err(DurableBeliefError::from)?;
        self.custody_usage.set(Some(SourceCustodyUsage {
            charged_read_bytes: custody.audit().charged_read_bytes(),
            io_calls: custody.audit().io_calls(),
            retained_bytes: custody.retained_bytes(),
        }));
        // Another slot publishing an equal manifest cannot replace this selected record.
        if !custody.matches_publication_record(
            self.slot,
            root,
            local.child_count as u64,
            local.record_digest,
        ) {
            return Err(DurableBeliefError::AuthorityChanged.into());
        }
        let maximum = usize::try_from(ceiling).unwrap_or(usize::MAX);
        let bytes = custody.read_belief_evidence(subject, maximum).map_err(|error| match error {
            BeliefEvidenceReadError::Missing => SourceHydrationError::NotReachable,
            BeliefEvidenceReadError::LimitExceeded => HydrationError::BudgetExceeded.into(),
            _ => SourceHydrationError::SourceMismatch,
        })?;
        self.check_head(pin, head)?;
        Ok(bytes)
    }
}

impl<C: Fn() -> bool + Sync> PublishedSourceReader for DeletionAwareSourceReader<'_, C> {
    fn validate_source_descriptor(
        &self,
        descriptor: &SemanticHandle,
    ) -> Result<(), SourceHydrationError> {
        if &descriptor.anchor != self.anchor {
            return Err(DurableBeliefError::AuthorityChanged.into());
        }
        Ok(())
    }

    fn read_published_source(
        &self,
        root: ContentDigest,
        subject: ContentDigest,
        ceiling: u64,
    ) -> Result<Vec<u8>, SourceHydrationError> {
        self.read(root, subject, ceiling)
    }
}

impl ReferenceHydrationCatalog {
    /// Registers a source binding using current deployment authority and committed deletion state.
    /// Registration is authority-owned. Only metadata is retained, never raw source bytes.
    pub fn bind_deployment_source_object<C: Fn() -> bool + Sync>(
        &mut self,
        handle_id: &str,
        descriptor_digest: ContentDigest,
        reader: &DeletionAwareSourceReader<'_, C>,
    ) -> Result<SourceObjectBinding, SourceHydrationError> {
        let descriptor = self.descriptor(handle_id, descriptor_digest)
            .ok_or(HydrationError::DescriptorNotFound)?;
        if &descriptor.anchor != reader.anchor {
            return Err(DurableBeliefError::AuthorityChanged.into());
        }
        let root = reader.deployment.publisher().root(reader.slot)
            .ok_or(DurableBeliefError::Selection)?.root;
        self.bind_source_object(handle_id, descriptor_digest, root, reader)
    }

    /// Admits the ordinary privacy/capability projection, retention, quote and cursor BEFORE
    /// native source I/O, then checks current ledger, committed deletions and complete custody.
    /// Returns the existing H3 artifact and receipt without caching payloads. Lower-level or
    /// unavailable delivery does not call the reader. A source failure never becomes absence,
    /// silent fallback, cursor consumption, repair, or completion of deletion. Existing cached
    /// non-source artifacts retain their ordinary catalog semantics, not new deletion proof.
    pub fn hydrate_from_deployment_source<C: Fn() -> bool + Sync>(
        &mut self,
        request: &HydrationRequest,
        reader: &DeletionAwareSourceReader<'_, C>,
        now: TimestampNs,
    ) -> Result<HydrationResponse, SourceHydrationError> {
        request.verify()?;
        if &request.anchor != reader.anchor {
            return Err(DurableBeliefError::AuthorityChanged.into());
        }
        self.hydrate_from_source(request, reader, now)
    }
}
