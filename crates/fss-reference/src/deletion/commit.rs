#![forbid(unsafe_code)]
//! `CAP-DELETE-COMMIT-001`: revalidate, record, retract, unlink, verify, complete.
//!
//! Order (root-last, reversed for removal):
//!
//! 1. Revalidate: the plan digest must equal the plan recomputed against the current head, and
//!    the approval must be its exact approval. Any change is a stale plan; any blocker refuses.
//!    Nothing is written before this point.
//! 2. Stage the sealed plan and append the deletion record batch: the `deletion_record` delta,
//!    one `deletion_tombstone` successor per exclusively deleted ledger object and one
//!    `local_root_retraction` successor per retracted root. From here on every reader resolves
//!    the closure to `deleted`; nothing in the ledger is rewritten.
//! 3. Unlink each retracted root record (roots directory fsynced), then each deletable object
//!    and its verification hold (spool directories fsynced).
//! 4. Verify that no removed name is still present, then stage and append the completion record.
//!
//! Every step is idempotent: a rerun after an interruption at any point finds the durable record,
//! skips what is already gone and appends byte-identical completion bytes exactly once.

use fss_core::{BatchId, ContentDigest, EvidenceDelta, ObjectId, Plane};
use fss_publication::{ROOT_RETRACTION_FAMILY, SlotName, root_reachability_object_id};

use super::index::DeletionIndex;
use super::plan::{DeletionCompletion, DeletionPlan, approval_digest};
use super::walk::Universe;
use super::{
    DeletionError, STAGE_DELETION_COMPLETE, STAGE_DELETION_COMPLETION_STAGED,
    STAGE_DELETION_OBJECT_REMOVED, STAGE_DELETION_PLAN_STAGED, STAGE_DELETION_RECORD_APPENDED,
    STAGE_DELETION_REVALIDATED, STAGE_DELETION_ROOT_RETRACTED,
};
use crate::reference_deployment::{
    FAMILY_DELETION_COMPLETION, FAMILY_DELETION_RECORD, FAMILY_DELETION_TOMBSTONE,
};
use crate::{ReferenceDeployment, ReplayCx};

/// How a commit call ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitOutcome {
    /// This call recorded, applied and completed the plan.
    Completed,
    /// A durable deletion record existed; this call finished it.
    Resumed,
    /// The completion record was already durable; nothing was written.
    AlreadyComplete,
}

impl CommitOutcome {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Resumed => "resumed",
            Self::AlreadyComplete => "already_complete",
        }
    }
}

/// Result of [`super::commit_deletion`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    /// How this call ended.
    pub outcome: CommitOutcome,
    /// Sealed plan identity.
    pub plan_digest: ContentDigest,
    /// The applied plan.
    pub plan: DeletionPlan,
    /// Completion record identity.
    pub completion_digest: ContentDigest,
    /// The completion record.
    pub completion: DeletionCompletion,
    /// Authority sequence after the call.
    pub authority_sequence: u64,
}

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<(), DeletionError> {
    cx.checkpoint(stage)
        .map_err(|_| DeletionError::Cancelled { stage })
}

fn batch_id(text: String) -> Result<BatchId, DeletionError> {
    Ok(BatchId::parse(text)?)
}

/// The deletion record batch: record, tombstones and retractions, deterministic from the plan.
fn record_deltas(
    plan: &DeletionPlan,
    plan_digest: ContentDigest,
) -> Result<Vec<EvidenceDelta>, DeletionError> {
    let mut deltas = Vec::with_capacity(plan.tombstones.len() + plan.retractions.len() + 1);
    deltas.push(EvidenceDelta {
        delta_id: format!("delta:deletion:{}", plan_digest.to_text()),
        family: FAMILY_DELETION_RECORD.to_owned(),
        object_id: ObjectId::parse(DeletionPlan::record_object_id(plan.import_identity))?,
        prior_generation: None,
        new_generation: 1,
        validity: plan.validity,
        plane: Plane::Authority,
        payload_digest: plan_digest,
        witness_digest: None,
        operation_id: None,
    });
    for tombstone in &plan.tombstones {
        let next = tombstone
            .prior_generation
            .checked_add(1)
            .ok_or(DeletionError::Bound {
                limit: "object_generation",
            })?;
        deltas.push(EvidenceDelta {
            delta_id: format!("delta:deletion-tombstone:{}", tombstone.object_id),
            family: FAMILY_DELETION_TOMBSTONE.to_owned(),
            object_id: ObjectId::parse(tombstone.object_id.clone())?,
            prior_generation: Some(tombstone.prior_generation),
            new_generation: next,
            validity: tombstone.validity,
            plane: tombstone.plane,
            payload_digest: plan_digest,
            witness_digest: None,
            operation_id: None,
        });
    }
    for retraction in &plan.retractions {
        let slot = SlotName::parse(&retraction.slot).map_err(|_| DeletionError::RecordMismatch)?;
        let object_id =
            root_reachability_object_id(&slot).map_err(|_| DeletionError::RecordMismatch)?;
        let new_generation = match retraction.prior_generation {
            Some(generation) => generation.checked_add(1).ok_or(DeletionError::Bound {
                limit: "object_generation",
            })?,
            None => 1,
        };
        deltas.push(EvidenceDelta {
            delta_id: format!("delta:local-root-retraction:{}", retraction.slot),
            family: ROOT_RETRACTION_FAMILY.to_owned(),
            object_id,
            prior_generation: retraction.prior_generation,
            new_generation,
            validity: retraction.validity,
            plane: Plane::Authority,
            payload_digest: plan_digest,
            witness_digest: Some(retraction.root),
            operation_id: None,
        });
    }
    Ok(deltas)
}

/// Finds the current plan whose digest is `plan_digest`, recomputed against the current head.
fn current_plan(
    deployment: &ReferenceDeployment,
    index: &DeletionIndex,
    plan_digest: ContentDigest,
    cx: &ReplayCx,
) -> Result<DeletionPlan, DeletionError> {
    let universe = Universe::scan(deployment, index, cx)?;
    for import in universe.imports() {
        let plan = universe.plan(deployment, *import)?;
        if plan.digest()? == plan_digest {
            return Ok(plan);
        }
    }
    Err(DeletionError::StalePlan(plan_digest))
}

pub(super) fn commit(
    deployment: &mut ReferenceDeployment,
    plan_digest: ContentDigest,
    approval: ContentDigest,
    principal: &str,
    cx: &ReplayCx,
) -> Result<CommitReceipt, DeletionError> {
    let index = DeletionIndex::read(deployment)?;
    if let Some(entry) = index.plan(plan_digest) {
        let plan = entry.plan.clone();
        if approval_digest(plan_digest, &plan.site_lineage, principal)? != approval {
            return Err(DeletionError::ApprovalMismatch(approval));
        }
        if let Some(completion_digest) = entry.completion_digest {
            let bytes = deployment.publisher().spool().read(completion_digest)?;
            let completion = DeletionCompletion::decode(&bytes, completion_digest)?;
            return Ok(CommitReceipt {
                outcome: CommitOutcome::AlreadyComplete,
                plan_digest,
                plan,
                completion_digest,
                completion,
                authority_sequence: deployment.current_anchor().commit_sequence,
            });
        }
        return apply(deployment, plan, plan_digest, CommitOutcome::Resumed, cx);
    }
    let plan = current_plan(deployment, &index, plan_digest, cx)?;
    if plan.site_lineage != deployment.site_lineage()
        || approval_digest(plan_digest, &plan.site_lineage, principal)? != approval
    {
        return Err(DeletionError::ApprovalMismatch(approval));
    }
    if !plan.blockers.is_empty() {
        return Err(DeletionError::Blocked(plan.blockers));
    }
    checkpoint(cx, STAGE_DELETION_REVALIDATED)?;
    let bytes = plan.canonical_bytes()?;
    let staged = deployment.stage_payload(&bytes)?;
    if staged != plan_digest {
        return Err(DeletionError::RecordMismatch);
    }
    checkpoint(cx, STAGE_DELETION_PLAN_STAGED)?;
    deployment.append_deletion_batch(
        batch_id(DeletionPlan::record_batch_id(plan_digest))?,
        record_deltas(&plan, plan_digest)?,
        vec![plan_digest],
        cx,
    )?;
    checkpoint(cx, STAGE_DELETION_RECORD_APPENDED)?;
    apply(deployment, plan, plan_digest, CommitOutcome::Completed, cx)
}

/// Steps 3 and 4 against a durable deletion record.
fn apply(
    deployment: &mut ReferenceDeployment,
    plan: DeletionPlan,
    plan_digest: ContentDigest,
    outcome: CommitOutcome,
    cx: &ReplayCx,
) -> Result<CommitReceipt, DeletionError> {
    deployment.publisher_mut().verify_object(plan_digest)?;
    for retraction in &plan.retractions {
        let slot = SlotName::parse(&retraction.slot).map_err(|_| DeletionError::RecordMismatch)?;
        if let Some(visible) = deployment.publisher().root(&slot)
            && visible.root != retraction.root
        {
            return Err(DeletionError::Incomplete {
                detail: format!(
                    "slot {} holds a root the deletion record does not name",
                    retraction.slot
                ),
            });
        }
        deployment
            .publisher_mut()
            .retract_root(&slot, plan_digest)?;
        checkpoint(cx, STAGE_DELETION_ROOT_RETRACTED)?;
    }
    for object in &plan.deletable {
        deployment
            .publisher_mut()
            .remove_deleted_object(object.digest, plan_digest)?;
        checkpoint(cx, STAGE_DELETION_OBJECT_REMOVED)?;
    }
    // Verify on the filesystem, not only in the index, before claiming anything.
    for object in &plan.deletable {
        if deployment
            .publisher()
            .spool()
            .state(object.digest)
            .is_some()
            || deployment.publisher().object_name_present(object.digest)
        {
            return Err(DeletionError::Incomplete {
                detail: format!("{} is still present in the spool", object.digest),
            });
        }
    }
    for retraction in &plan.retractions {
        let slot = SlotName::parse(&retraction.slot).map_err(|_| DeletionError::RecordMismatch)?;
        let record = deployment
            .publisher()
            .root_dir()
            .join(fss_publication::LOCAL_ROOTS_DIR)
            .join(format!(
                "{}{}",
                retraction.slot,
                fss_publication::ROOT_RECORD_SUFFIX
            ));
        if deployment.publisher().root(&slot).is_some() || record.exists() {
            return Err(DeletionError::Incomplete {
                detail: format!("root {} is still published", retraction.slot),
            });
        }
    }
    let completion = DeletionCompletion::of(&plan)?;
    let completion_bytes = completion.canonical_bytes()?;
    let completion_digest = deployment.stage_payload(&completion_bytes)?;
    checkpoint(cx, STAGE_DELETION_COMPLETION_STAGED)?;
    deployment.append_deletion_batch(
        batch_id(DeletionPlan::completion_batch_id(plan_digest))?,
        vec![EvidenceDelta {
            delta_id: format!("delta:deletion-complete:{}", plan_digest.to_text()),
            family: FAMILY_DELETION_COMPLETION.to_owned(),
            object_id: ObjectId::parse(DeletionPlan::record_object_id(plan.import_identity))?,
            prior_generation: Some(1),
            new_generation: 2,
            validity: plan.validity,
            plane: Plane::Authority,
            payload_digest: completion_digest,
            witness_digest: Some(plan_digest),
            operation_id: None,
        }],
        vec![completion_digest, plan_digest],
        cx,
    )?;
    // No fallible work after the completion record: cancellation cannot erase success.
    cx.checkpoint_post_commit(STAGE_DELETION_COMPLETE);
    Ok(CommitReceipt {
        outcome,
        plan_digest,
        plan,
        completion_digest,
        completion,
        authority_sequence: deployment.current_anchor().commit_sequence,
    })
}
