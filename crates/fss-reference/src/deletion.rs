#![forbid(unsafe_code)]
//! Graph-complete deletion closure of one retained import, or of every retained import of one
//! sensor or one event (FSS-037, `CAP-DELETE-PREPARE-001`, `CAP-DELETE-COMMIT-001`,
//! `PUB-DELETE-001`).
//!
//! [`plan_deletion`] (one import) and [`plan_scope_deletion`] (a [`DeletionScope`]) are
//! read-only: each walks every retained reference of the deployment (the `walk` module documents
//! the rule) and returns a sealed, canonical, digest-bound
//! [`DeletionPlan`]: the closure units and why each was reached, the spool objects removed and
//! their bytes, the closure objects retained (shared with retained authority, or authority
//! history), the ledger tombstones and root retractions of the deletion record, the events whose
//! history is kept, the blockers, and the copies this deployment cannot delete or enumerate.
//!
//! [`commit_deletion`] revalidates the plan against the current head (any change is a stale plan),
//! appends the deletion record first, then unlinks, verifies and appends the completion record;
//! it resumes idempotently after an interruption at any point.
//!
//! What it proves and what it does not:
//!
//! - Bytes are unlinked from the local filesystem (`filesystem_unlink`). The spool is not
//!   encrypted, so nothing here is cryptographic erasure; filesystem-level recovery, snapshots,
//!   backups and device remanence are out of scope and stated so in every record.
//! - The ledger is append-only: batches that named deleted content stay; their objects get a
//!   `deletion_tombstone` successor and deleted digests resolve to the `deleted` availability.
//! - Events keep every committed revision. No new event revision is minted: a revision is a
//!   decision about the world under a decision path, while deletion changes custody, not the
//!   decision; availability stays orthogonal to knowledge state. Their evidence handles resolve
//!   to `deleted`, and `fss orient` / `fss explain` say so.
//! - Unknown copies are named, never ignored: the original input file, unrecorded operator
//!   exports, and any alert that may have been transmitted.
//! - A sensor or event scope ([`scope`]) is one plan over the union of its member imports'
//!   closures, one tombstone batch and one completion record, under the same commit, approval,
//!   stale-plan, tombstone-first and exactly-once guarantees. Evidence holds ([`holds`]) stay
//!   import-scoped: an active hold on any member import (or on an import whose held closure the
//!   scoped plan would touch) blocks the whole scoped plan.

mod commit;
/// Approval-gated preservation of retained imports and their shared derivative closures.
pub mod holds;
mod index;
mod plan;
pub mod scope;
mod walk;

use std::fmt;

use fss_core::{ContentDigest, ContractError};
use fss_object::SpoolError;
use fss_publication::LocalPublicationError;

pub use commit::{CommitOutcome, CommitReceipt};
pub use index::{DeletionEntry, DeletionIndex, has_records};
pub use plan::{
    ClosureUnit, DELETION_APPROVAL_DOMAIN, DELETION_COMPLETION_DOMAIN, DELETION_MECHANISM,
    DELETION_OUT_OF_SCOPE, DELETION_PLAN_DOMAIN, DELETION_SCOPE_COMPLETION_DOMAIN,
    DELETION_SCOPE_PLAN_DOMAIN, DeletableObject, DeletionCompletion, DeletionPlan, EventReference,
    Finding, MAX_DELETION_RECORD_BYTES, ObjectTombstone, RetainedObject, RootRetraction,
    Unattributed, approval_digest,
};
pub use scope::DeletionScope;

use crate::{ReferenceDeployment, ReferenceError, ReplayCx};

/// Cooperative checkpoint of the read-only reference scan.
pub const STAGE_DELETION_SCAN: &str = "deletion:scan";
/// Cut point: plan revalidated and approved; nothing written yet.
pub const STAGE_DELETION_REVALIDATED: &str = "deletion:revalidated";
/// Cut point: sealed plan staged in custody; no authority yet.
pub const STAGE_DELETION_PLAN_STAGED: &str = "deletion:plan_staged";
/// Cut point: deletion record (tombstones, retractions) durable; no byte removed yet.
pub const STAGE_DELETION_RECORD_APPENDED: &str = "deletion:record_appended";
/// Cut point: after each root record is unlinked.
pub const STAGE_DELETION_ROOT_RETRACTED: &str = "deletion:root_retracted";
/// Cut point: after each object is unlinked.
pub const STAGE_DELETION_OBJECT_REMOVED: &str = "deletion:object_removed";
/// Cut point: completion record staged; not yet appended.
pub const STAGE_DELETION_COMPLETION_STAGED: &str = "deletion:completion_staged";
/// Post-commit checkpoint after the completion record (never reported as a failure).
pub const STAGE_DELETION_COMPLETE: &str = "deletion:complete";
/// Every cut point of [`commit_deletion`], in execution order.
pub const DELETION_CUT_POINTS: &[&str] = &[
    STAGE_DELETION_REVALIDATED,
    STAGE_DELETION_PLAN_STAGED,
    STAGE_DELETION_RECORD_APPENDED,
    STAGE_DELETION_ROOT_RETRACTED,
    STAGE_DELETION_OBJECT_REMOVED,
    STAGE_DELETION_COMPLETION_STAGED,
];

/// Typed deletion refusal; no refusal before the deletion record writes anything.
#[derive(Debug)]
pub enum DeletionError {
    /// The import was already deleted; its evidence is `deleted`.
    EvidenceDeleted {
        /// Deleted import.
        import: ContentDigest,
        /// Plan that deleted it.
        plan: ContentDigest,
    },
    /// No completed, retained import has this identity.
    UnknownImport(ContentDigest),
    /// A sensor or event scope reaches no completed, retained import (unknown sensor or event,
    /// or every member already deleted); nothing was written.
    ScopeEmpty(String),
    /// No plan recomputed against the current head has this digest (stale or unknown).
    StalePlan(ContentDigest),
    /// The approval is not the exact approval of this plan for this principal.
    ApprovalMismatch(ContentDigest),
    /// The plan has blockers; nothing was written.
    Blocked(Vec<Finding>),
    /// A hard bound was exceeded.
    Bound {
        /// Bound name.
        limit: &'static str,
    },
    /// A retained deletion record does not match its ledger delta.
    RecordMismatch,
    /// Cooperative cancellation at a cut point; rerun the commit to resume.
    Cancelled {
        /// Cut point reached.
        stage: &'static str,
    },
    /// Removal could not be verified; nothing claims completion. Rerun to resume.
    Incomplete {
        /// What is still present.
        detail: String,
    },
    /// Shared contract failure.
    Contract(ContractError),
    /// Deployment authority failure.
    Reference(ReferenceError),
    /// Local publication failure.
    Publication(LocalPublicationError),
    /// Spool custody failure.
    Spool(SpoolError),
    /// Hold state cannot be verified; no deletion may assume it is absent.
    Hold(Box<holds::HoldError>),
}

impl DeletionError {
    /// Registered stable identity (registries/ERRORS.md).
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
        match self {
            Self::EvidenceDeleted { .. } => "ERR-EVIDENCE-DELETED-001",
            Self::UnknownImport(_) => "ERR-DELETION-IMPORT-UNKNOWN-001",
            Self::ScopeEmpty(_) => "ERR-DELETION-SCOPE-EMPTY-001",
            Self::StalePlan(_) => "ERR-DELETION-PLAN-STALE-001",
            Self::ApprovalMismatch(_) => "ERR-DELETION-APPROVAL-001",
            Self::Blocked(_) => "ERR-DELETION-BLOCKED-001",
            Self::Bound { .. } => "ERR-DELETION-BOUND-001",
            Self::Cancelled { .. } | Self::Incomplete { .. } => "ERR-DELETION-INCOMPLETE-001",
            Self::Hold(error) => error.stable_id(),
            Self::RecordMismatch
            | Self::Contract(_)
            | Self::Reference(_)
            | Self::Publication(_)
            | Self::Spool(_) => "ERR-DELETION-STORAGE-001",
        }
    }
}

impl fmt::Display for DeletionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EvidenceDeleted { import, plan } => write!(
                f,
                "import {import} was deleted under deletion plan {plan}; its evidence is deleted"
            ),
            Self::UnknownImport(import) => {
                write!(f, "no completed retained import has identity {import}")
            }
            Self::ScopeEmpty(scope) => write!(
                f,
                "deletion scope {scope} reaches no completed retained import (unknown, or every \
                 member import is already deleted)"
            ),
            Self::StalePlan(plan) => write!(
                f,
                "no deletion plan recomputed against the current head has digest {plan}; the \
                 deployment changed since planning (or the plan is unknown): plan again"
            ),
            Self::ApprovalMismatch(approval) => write!(
                f,
                "approval {approval} is not the exact approval of this plan for this principal"
            ),
            Self::Blocked(blockers) => {
                write!(f, "deletion blocked by {} blocker(s):", blockers.len())?;
                for blocker in blockers {
                    write!(
                        f,
                        " [{} {}: {}]",
                        blocker.kind, blocker.subject, blocker.detail
                    )?;
                }
                Ok(())
            }
            Self::Bound { limit } => write!(f, "deletion bound exceeded: {limit}"),
            Self::RecordMismatch => {
                f.write_str("a retained deletion record does not match its ledger delta")
            }
            Self::Cancelled { stage } => write!(
                f,
                "deletion interrupted at {stage}; rerun the same commit to resume"
            ),
            Self::Incomplete { detail } => write!(
                f,
                "deletion not verified complete ({detail}); rerun the same commit to resume"
            ),
            Self::Contract(error) => write!(f, "contract error: {error}"),
            Self::Reference(error) => write!(f, "deployment error: {error}"),
            Self::Publication(error) => write!(f, "publication error: {error}"),
            Self::Spool(error) => write!(f, "spool error: {error}"),
            Self::Hold(error) => write!(f, "evidence hold: {error}"),
        }
    }
}

impl std::error::Error for DeletionError {}

impl From<ContractError> for DeletionError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}
impl From<ReferenceError> for DeletionError {
    fn from(value: ReferenceError) -> Self {
        Self::Reference(value)
    }
}
impl From<LocalPublicationError> for DeletionError {
    fn from(value: LocalPublicationError) -> Self {
        Self::Publication(value)
    }
}
impl From<SpoolError> for DeletionError {
    fn from(value: SpoolError) -> Self {
        Self::Spool(value)
    }
}

impl From<holds::HoldError> for DeletionError {
    fn from(value: holds::HoldError) -> Self {
        Self::Hold(Box::new(value))
    }
}

/// Computes the sealed deletion plan of `import` (`CAP-DELETE-PREPARE-001`). Writes nothing.
pub fn plan_deletion(
    deployment: &ReferenceDeployment,
    import: ContentDigest,
    cx: &ReplayCx,
) -> Result<DeletionPlan, DeletionError> {
    plan_scope_deletion(deployment, &DeletionScope::Import(import), cx)
}

/// Computes the sealed deletion plan of `scope` (`CAP-DELETE-PREPARE-001`): one import, or the
/// union closure of every retained import of a sensor or an event. Writes nothing.
pub fn plan_scope_deletion(
    deployment: &ReferenceDeployment,
    scope: &DeletionScope,
    cx: &ReplayCx,
) -> Result<DeletionPlan, DeletionError> {
    let index = DeletionIndex::read(deployment)?;
    if let DeletionScope::Import(import) = scope
        && let Some(entry) = index.import(*import)
    {
        return Err(DeletionError::EvidenceDeleted {
            import: *import,
            plan: entry.plan_digest,
        });
    }
    let holds = holds::HoldIndex::read(deployment, cx)?;
    let universe = walk::Universe::scan(deployment, &index, cx)?;
    let plan = universe.plan(deployment, scope)?;
    holds.protect(&universe, deployment, plan, cx)
}

/// Executes a sealed plan under its exact approval (`CAP-DELETE-COMMIT-001`); resumes an
/// interrupted commit of the same plan. The `commit` module documents the ordering.
pub fn commit_deletion(
    deployment: &mut ReferenceDeployment,
    plan_digest: ContentDigest,
    approval: ContentDigest,
    principal: &str,
    cx: &ReplayCx,
) -> Result<CommitReceipt, DeletionError> {
    commit::commit(deployment, plan_digest, approval, principal, cx)
}

#[cfg(test)]
mod tests;
