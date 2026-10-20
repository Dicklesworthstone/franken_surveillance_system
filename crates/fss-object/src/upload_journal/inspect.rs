#![forbid(unsafe_code)]
//! Read-only, authority-metered projection of the same verified recovery history.

mod read_io;

use std::collections::BTreeMap;
use std::path::Path;

use fss_core::{
    BudgetVector, ContentDigest, ObligationState, RegionTree, RuntimeGrant, TimestampNs,
};
use fss_runtime::authority::AuthorityCx;

use crate::multipart::{
    MultipartError, MultipartPhase, MultipartRecovery, UploadIntent, UploadJournalPin,
};
use crate::spool::{inspect_with_io, read_verified_payload};

use super::{
    ReplayedRecords, UploadJournalLimits, decode_record, inspect_layout, namespace_binding,
    persistence, validate_pin, verify_identities,
};
use read_io::ReadAuthorityIo;

/// Redacted recovery metadata. No provider upload ID, ETag, owner note or raw
/// checkpoint is retained by this result, including its debug representation.
#[derive(Clone, Debug, PartialEq)]
pub struct UploadJournalInspection {
    intent: UploadIntent,
    phase: MultipartPhase,
    confirmed_parts: usize,
    total_parts: usize,
    consumed: BudgetVector,
    remaining: BudgetVector,
    head: UploadJournalPin,
    records: usize,
    observed_at: TimestampNs,
    inspected_at: TimestampNs,
    orphaned_staging: usize,
    namespace: ContentDigest,
    namespace_bound: bool,
    locally_settled: bool,
    reconciliation: Option<ContentDigest>,
    cancelled: bool,
    deadline: Option<TimestampNs>,
}

impl UploadJournalInspection {
    /// Exact immutable operation, resource, plan and manifest identity.
    #[must_use]
    pub fn intent(&self) -> &UploadIntent {
        &self.intent
    }
    /// Last durable provider-protocol phase; independent of local obligation settlement.
    #[must_use]
    pub const fn phase(&self) -> MultipartPhase {
        self.phase
    }
    /// Number of durably acknowledged part checksums, without opaque provider tokens.
    #[must_use]
    pub const fn confirmed_parts(&self) -> usize {
        self.confirmed_parts
    }
    /// Number of parts required by the exact immutable plan.
    #[must_use]
    pub const fn total_parts(&self) -> usize {
        self.total_parts
    }
    /// Historical provider-transfer consumption, excluding this inspection's work.
    #[must_use]
    pub const fn consumed(&self) -> BudgetVector {
        self.consumed
    }
    /// Preserved original transfer allowance less all durable historical consumption.
    #[must_use]
    pub const fn remaining(&self) -> BudgetVector {
        self.remaining
    }
    /// Latest complete verified record, containing the supplied independent minimum.
    #[must_use]
    pub const fn head(&self) -> UploadJournalPin {
        self.head
    }
    /// Number of complete committed records in the verified contiguous history.
    #[must_use]
    pub const fn records(&self) -> usize {
        self.records
    }
    /// Latest time durably observed by the uploader, not the inspection time.
    #[must_use]
    pub const fn observed_at(&self) -> TimestampNs {
        self.observed_at
    }
    /// Torn staging files retained and charged, never treated as committed checkpoints.
    #[must_use]
    pub const fn orphaned_staging_count(&self) -> usize {
        self.orphaned_staging
    }
    /// Physical namespace attestation for explicit legacy adoption.
    #[must_use]
    pub const fn namespace_binding(&self) -> ContentDigest {
        self.namespace
    }
    /// Whether a v2 record durably binds this exact original directory and lock.
    #[must_use]
    pub const fn namespace_binding_verified(&self) -> bool {
        self.namespace_bound
    }
    /// A valid v1-only chain can be inspected but cannot resume without explicit adoption.
    #[must_use]
    pub const fn legacy_read_only(&self) -> bool {
        !self.namespace_bound
    }
    /// Whether the owner durably recorded terminal or indeterminate local settlement.
    #[must_use]
    pub const fn locally_settled(&self) -> bool {
        self.locally_settled
    }
    /// Durable indeterminate follow-up reference, without free-form notes.
    #[must_use]
    pub const fn reconciliation_reference(&self) -> Option<ContentDigest> {
        self.reconciliation
    }
    /// Whether cancellation was observed at any durable uploader boundary.
    #[must_use]
    pub const fn cancelled(&self) -> bool {
        self.cancelled
    }
    /// Preserved latest narrowed deadline.
    #[must_use]
    pub const fn deadline(&self) -> Option<TimestampNs> {
        self.deadline
    }
    /// Safe next action suggested by durable knowledge and caller-attested current time.
    /// This message grants no authority to perform the action.
    #[must_use]
    pub fn next_action(&self) -> &'static str {
        if !self.namespace_bound {
            return "retire legacy writers and explicitly adopt the original namespace before recovery";
        }
        if self.reconciliation.is_some() {
            return "retain the durable indeterminate reference for separately authorized reconciliation";
        }
        if self.locally_settled {
            return "restore and close the already recorded local receipt without provider dispatch";
        }
        match self.phase {
            MultipartPhase::Uncertain(_) => {
                "reconcile the exact outstanding dispatch before any new provider effect"
            }
            MultipartPhase::Completed => {
                "settle the recorded provider completion locally; retrievability remains unproven"
            }
            MultipartPhase::Aborted => {
                "settle the recorded abort locally without another provider abort"
            }
            MultipartPhase::Prepared | MultipartPhase::Uploading
                if self.cancelled || self.deadline.is_some_and(|at| self.inspected_at >= at) =>
            {
                "recover only for bounded cancellation or abort settlement; new payload work is refused"
            }
            MultipartPhase::Prepared => {
                "recover with the preserved remaining allowance before initiating the exact intent"
            }
            MultipartPhase::Uploading => {
                "recover with the preserved remaining allowance and continue only missing planned parts"
            }
        }
    }
}

/// Inspects an existing spool without creating, locking, syncing, repairing or
/// contacting a provider. Every filesystem operation and bounded read is charged
/// to the actual live `ObserveStatus` authority. Its principal may differ from the
/// uploader's, but `resource` must equal both its grant and the durable upload target.
///
/// A v1 chain remains readable and is explicitly labelled unbound. A mismatched
/// v2 namespace, bad independent minimum, fork, unknown version, oversize record,
/// clock regression, expired authority or incomplete/corrupt layout is refused.
/// Reads are descriptor-bound on supported Linux hosts and never take a writer lock;
/// a concurrent mutation can therefore cause a refusal rather than a guessed status.
pub fn inspect_upload_journal(
    root: &Path,
    limits: UploadJournalLimits,
    minimum: UploadJournalPin,
    resource: &str,
    authority: &mut AuthorityCx,
    tree: &RegionTree,
    now: TimestampNs,
) -> Result<UploadJournalInspection, MultipartError> {
    validate_pin(minimum)?;
    let spool_limits = limits.spool_limits()?;
    admit(authority, tree, now, resource, RuntimeGrant::ObserveStatus)?;
    let mut io = ReadAuthorityIo::new(authority, tree, now, resource, limits.max_read_bytes)?;
    let identities = inspect_layout(&io, root)?;
    io.pin_layout(root, &identities)?;
    let namespace = namespace_binding(root, &identities)?;
    let inspection = inspect_with_io(root, &spool_limits, &io).map_err(persistence)?;
    if inspection.missing_layout
        || inspection.holds_migration_pending
        || inspection.over_capacity
        || !inspection.report.corrupt.is_empty()
        || !inspection.report.foreign.is_empty()
        || inspection.report.admitted.len() > limits.max_records
    {
        return Err(persistence(
            "upload journal inspection refused invalid or over-bound layout",
        ));
    }
    let orphaned_staging = inspection.report.orphaned_staging.len();
    let mut records = BTreeMap::new();
    let mut decoded_bytes = 0_u64;
    for digest in inspection.report.admitted {
        let bytes = read_verified_payload(root, digest, spool_limits.max_object_bytes, &io)
            .map_err(persistence)?;
        decoded_bytes = decoded_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| persistence("upload journal inspection byte overflow"))?;
        if decoded_bytes > limits.max_total_bytes {
            return Err(persistence("upload journal exceeds total byte bound"));
        }
        let record = decode_record(&bytes, limits.max_checkpoint_bytes)?;
        if records.insert(record.sequence, (digest, record)).is_some() {
            return Err(persistence(
                "upload journal has competing records at one sequence",
            ));
        }
    }
    let replay = ReplayedRecords::validate(records, minimum, namespace)?;
    let recovery = MultipartRecovery::read(&replay, minimum)?;
    if recovery.intent().resource() != resource {
        return Err(MultipartError::OwnerMismatch);
    }
    if now < recovery.observed_at() {
        return Err(MultipartError::ClockRegression);
    }
    verify_identities(&io, &identities)?;
    let owner_state = recovery.owner_state()?;
    Ok(UploadJournalInspection {
        intent: recovery.intent().clone(),
        phase: recovery.phase(),
        confirmed_parts: recovery.confirmed_parts(),
        total_parts: recovery.plan().chunks.len(),
        consumed: recovery.consumed(),
        remaining: recovery.remaining_budget(),
        head: recovery.head(),
        records: replay.pins.len(),
        observed_at: recovery.observed_at(),
        inspected_at: now,
        orphaned_staging,
        namespace,
        namespace_bound: replay.namespace_bound,
        locally_settled: owner_state.is_some_and(|state| state != ObligationState::Pending),
        reconciliation: recovery.reconciliation_reference()?,
        cancelled: recovery.cancelled() || recovery.owner_cancelled()?,
        deadline: recovery.deadline(),
    })
}

pub(super) fn admit(
    authority: &AuthorityCx,
    tree: &RegionTree,
    now: TimestampNs,
    resource: &str,
    grant: RuntimeGrant,
) -> Result<(), MultipartError> {
    if resource.is_empty() || resource.len() > 1024 || resource.chars().any(char::is_control) {
        return Err(MultipartError::OwnerMismatch);
    }
    let cancelled = authority.is_cancel_requested(tree).map_err(persistence)?;
    let node = tree.get(authority.region()).map_err(persistence)?;
    if cancelled
        || now < node.created_at
        || node.drain_requested_at.is_some_and(|at| now < at)
        || node.closed_at.is_some_and(|at| now < at)
        || node.authority.deadline.is_some_and(|at| now >= at)
    {
        return Err(persistence(
            "upload journal inspection authority is inactive or expired",
        ));
    }
    authority
        .require_grant_for(grant, resource)
        .map_err(persistence)
}
