#![forbid(unsafe_code)]
//! Request-owned admission for the existing canonical deletion proof reader.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use fss_core::{ContentDigest, EvidenceDeltaBatch};
use fss_ledger::DurableReferenceLedger;
use fss_publication::custody_audit::MAX_AUDIT_ROOTS;
use fss_publication::custody_audit::belief_snapshot::durable::{
    DurableBeliefDeletionAuthority, DurableBeliefError,
};
use fss_publication::{LocalRootPublisher, SlotName};

use crate::deletion::index::proof;
use crate::deletion::plan::MAX_DELETION_RECORD_BYTES;
use crate::deletion::{DeletionError, DeletionPlan};
use crate::reference_deployment::{
    FAMILY_DELETION_COMPLETION, FAMILY_DELETION_RECORD, FAMILY_DELETION_TOMBSTONE,
};

/// Additional logical admission limits for one deletion-history validation. Zero refuses work in
/// that dimension. The canonical record decoder retains its independent format/list bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeletionBeliefLimits {
    /// Maximum committed batches inspected, including unrelated and empty batches.
    pub max_history_batches: usize,
    /// Maximum delta and child-reference entries across the entire history.
    pub max_history_entries: usize,
    /// Maximum plan/completion payload read attempts, including failed attempts.
    pub max_record_reads: usize,
    /// Maximum payload bytes per read, enforced by the native spool before allocation.
    pub max_record_bytes: usize,
    /// Aggregate payload-byte allowance; a failed read consumes its whole reserved allowance.
    pub max_total_record_bytes: usize,
    /// Maximum total top-level plan-list entries admitted before transition reconstruction.
    /// This bounds retained semantic rows, not decoder scratch or allocator overhead.
    pub max_plan_entries: usize,
    /// Maximum distinct denied objects inserted into the result map.
    pub max_denied_objects: usize,
}

impl Default for DeletionBeliefLimits {
    fn default() -> Self {
        Self {
            max_history_batches: 256,
            max_history_entries: 16_384,
            max_record_reads: 512,
            max_record_bytes: MAX_DELETION_RECORD_BYTES,
            max_total_record_bytes: 64 * 1024 * 1024,
            max_plan_entries: 131_072,
            max_denied_objects: 65_536,
        }
    }
}

/// Cumulative logical reservations available after success, cancellation, or refusal. These are
/// not filesystem syscall counts, envelope bytes, hashing CPU, or measured allocator usage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeletionBeliefUsage {
    /// Admitted history batches.
    pub history_batches: usize,
    /// Admitted history deltas plus child references.
    pub history_entries: usize,
    /// Admitted record-read attempts.
    pub record_reads: usize,
    /// Successful payload lengths plus unrefunded allowances of failed reads.
    pub record_bytes: usize,
    /// Top-level plan-list entries admitted before expected transitions are allocated.
    pub plan_entries: usize,
    /// Distinct denied objects inserted before success or refusal.
    pub denied_objects: usize,
}

/// A single-use, verifier-owned deletion authority with cancellation and non-refillable accounting.
/// Use this owner with `verify_durable_belief_with_deletion_authority` to retain usage even when
/// verification refuses. Constructing a new owner is a new explicit admission, not an implicit retry.
///
/// Cancellation is checked throughout history traversal, between bounded record reads/decodes,
/// and while assembling denials. A single native read or bounded canonical decode is synchronous;
/// this owner does not claim to preempt it. No source content, repair, or mutation is requested.
pub struct BoundedCommittedDeletionBeliefAuthority<'a, C: Fn() -> bool + ?Sized> {
    limits: DeletionBeliefLimits,
    cancelled: &'a C,
    attempted: Cell<bool>,
    usage: Cell<DeletionBeliefUsage>,
}

impl<'a, C: Fn() -> bool + ?Sized> BoundedCommittedDeletionBeliefAuthority<'a, C> {
    /// Creates a request-owned allowance. Native record reads never exceed the canonical format
    /// ceiling, even when the caller supplies a larger per-record allowance.
    #[must_use]
    pub fn new(limits: DeletionBeliefLimits, cancelled: &'a C) -> Self {
        Self {
            limits,
            cancelled,
            attempted: Cell::new(false),
            usage: Cell::new(DeletionBeliefUsage::default()),
        }
    }

    /// Work remains available after any refusal and is never reset by another call.
    #[must_use]
    pub fn usage(&self) -> DeletionBeliefUsage {
        self.usage.get()
    }

    /// Whether the single admission attempt has started, including an initially cancelled one.
    #[must_use]
    pub fn attempted(&self) -> bool {
        self.attempted.get()
    }

    fn checkpoint(&self) -> Result<(), DurableBeliefError> {
        if (self.cancelled)() {
            Err(DurableBeliefError::Cancelled)
        } else {
            Ok(())
        }
    }

    fn charge(
        &self,
        count: usize,
        maximum: usize,
        name: &'static str,
        field: fn(&mut DeletionBeliefUsage) -> &mut usize,
    ) -> Result<(), DurableBeliefError> {
        let mut usage = self.usage.get();
        let used = field(&mut usage);
        let next = used
            .checked_add(count)
            .filter(|next| *next <= maximum)
            .ok_or(DurableBeliefError::Limit(name))?;
        *used = next;
        self.usage.set(usage);
        Ok(())
    }

    fn read_record(
        &self,
        digest: ContentDigest,
        read: &mut impl FnMut(ContentDigest, usize) -> Result<Vec<u8>, DurableBeliefError>,
    ) -> Result<Vec<u8>, DurableBeliefError> {
        self.checkpoint()?;
        self.charge(
            1,
            self.limits.max_record_reads,
            "deletion record reads",
            |u| &mut u.record_reads,
        )?;
        let remaining = self.limits.max_total_record_bytes - self.usage.get().record_bytes;
        let allowance = self
            .limits
            .max_record_bytes
            .min(MAX_DELETION_RECORD_BYTES)
            .min(remaining);
        if allowance == 0 {
            return Err(DurableBeliefError::Limit("deletion record bytes"));
        }
        self.charge(
            allowance,
            self.limits.max_total_record_bytes,
            "deletion record bytes",
            |u| &mut u.record_bytes,
        )?;
        // Reserve before I/O. An error cannot refund unknown work into a retry loop.
        let bytes = read(digest, allowance)?;
        if bytes.len() > allowance {
            return Err(DurableBeliefError::DeletionAuthorityInvalid);
        }
        let mut usage = self.usage.get();
        usage.record_bytes -= allowance - bytes.len();
        self.usage.set(usage);
        self.checkpoint()?;
        Ok(bytes)
    }

    fn admit_plan(&self, plan: &DeletionPlan) -> Result<(), DurableBeliefError> {
        self.checkpoint()?;
        for count in [
            plan.imports.len(),
            plan.units.len(),
            plan.deletable.len(),
            plan.retained.len(),
            plan.tombstones.len(),
            plan.retractions.len(),
            plan.events.len(),
            plan.blockers.len(),
            plan.unknown_copies.len(),
        ] {
            self.charge(
                count,
                self.limits.max_plan_entries,
                "deletion plan entries",
                |u| &mut u.plan_entries,
            )?;
        }
        Ok(())
    }

    /// Reuses the canonical deletion owner for a caller-verified, read-only committed history.
    /// The reader must rehash each exact object and enforce the supplied allocation ceiling.
    /// Admission remains single-use and charges the same counters as the durable adapter.
    pub(crate) fn verified_denials_from_batches(
        &self,
        batches: &[EvidenceDeltaBatch],
        slots: &[SlotName],
        mut read: impl FnMut(ContentDigest, usize) -> Result<Vec<u8>, DurableBeliefError>,
    ) -> Result<BTreeMap<ContentDigest, ContentDigest>, DurableBeliefError> {
        if self.attempted.replace(true) {
            return Err(DurableBeliefError::Limit("deletion admission attempts"));
        }
        self.checkpoint()?;
        if slots.len() > MAX_AUDIT_ROOTS {
            return Err(DurableBeliefError::Limit("deletion selected slots"));
        }
        if !slots.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(DurableBeliefError::Selection);
        }
        let selected: BTreeSet<&str> = slots.iter().map(SlotName::as_str).collect();
        // Complete admission precedes every metadata read, including for a standalone trait call.
        for batch in batches {
            self.checkpoint()?;
            self.charge(
                1,
                self.limits.max_history_batches,
                "deletion history batches",
                |u| &mut u.history_batches,
            )?;
            for count in [batch.deltas.len(), batch.children.len()] {
                self.charge(
                    count,
                    self.limits.max_history_entries,
                    "deletion history entries",
                    |u| &mut u.history_entries,
                )?;
            }
            for delta in &batch.deltas {
                self.checkpoint()?;
                // A future/misspelled family cannot become an empty denial set.
                if delta.family.starts_with("deletion_")
                    && !matches!(
                        delta.family.as_str(),
                        FAMILY_DELETION_RECORD
                            | FAMILY_DELETION_TOMBSTONE
                            | FAMILY_DELETION_COMPLETION
                    )
                {
                    return Err(DurableBeliefError::DeletionAuthorityInvalid);
                }
            }
        }
        let entries = proof::read_controlled(
            batches,
            |digest| self.read_record(digest, &mut read).map_err(ProofFailure),
            || self.checkpoint().map_err(ProofFailure),
            |plan| self.admit_plan(plan).map_err(ProofFailure),
        )
        .map_err(|failure| failure.0)?;
        let mut denied = BTreeMap::new();
        for entry in entries {
            // Revocation is a SLOT decision, not a property of the shared content digest.
            // A durable header suffices even before its retraction deltas have been appended.
            // Do not globally deny the root: another authorized slot may legitimately retain it.
            for retraction in &entry.plan.retractions {
                self.checkpoint()?;
                if selected.contains(retraction.slot.as_str()) {
                    return Err(DurableBeliefError::Selection);
                }
            }
            for object in &entry.plan.deletable {
                self.checkpoint()?;
                if let Some(previous) = denied.get(&object.digest) {
                    if *previous != entry.plan_digest {
                        return Err(DurableBeliefError::DeletionAuthorityInvalid);
                    }
                    continue;
                }
                self.charge(
                    1,
                    self.limits.max_denied_objects,
                    "deletion denied objects",
                    |u| &mut u.denied_objects,
                )?;
                denied.insert(object.digest, entry.plan_digest);
            }
        }
        self.checkpoint()?;
        Ok(denied)
    }
}

struct ProofFailure(DurableBeliefError);
impl From<DeletionError> for ProofFailure {
    fn from(_: DeletionError) -> Self {
        Self(DurableBeliefError::DeletionAuthorityInvalid)
    }
}

impl<C: Fn() -> bool + ?Sized> DurableBeliefDeletionAuthority
    for BoundedCommittedDeletionBeliefAuthority<'_, C>
{
    fn verified_denials(
        &self,
        ledger: &DurableReferenceLedger,
        publisher: &LocalRootPublisher,
    ) -> Result<BTreeMap<ContentDigest, ContentDigest>, DurableBeliefError> {
        self.verified_denials_from_batches(ledger.batches(), &[], |digest, allowance| {
            publisher
                .spool()
                .read_bounded(digest, allowance)
                .map_err(|_| DurableBeliefError::DeletionAuthorityInvalid)
        })
    }

    fn verified_denials_for_slots(
        &self,
        ledger: &DurableReferenceLedger,
        publisher: &LocalRootPublisher,
        slots: &[SlotName],
    ) -> Result<BTreeMap<ContentDigest, ContentDigest>, DurableBeliefError> {
        self.verified_denials_from_batches(ledger.batches(), slots, |digest, allowance| {
            publisher
                .spool()
                .read_bounded(digest, allowance)
                .map_err(|_| DurableBeliefError::DeletionAuthorityInvalid)
        })
    }
}
