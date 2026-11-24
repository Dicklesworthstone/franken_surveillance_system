#![forbid(unsafe_code)]
//! Staging, root-last publication, and guarded authority-batch commits for [`super::ReferenceDeployment`].

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, EvidenceDeltaBatch, LedgerAnchor, Plane,
};
use fss_ledger::{AppendPhase, DurableLedgerError};
use fss_object::ObjectManifest;
use fss_publication::{
    AuthorityPublisher, LedgerCutPoint, LedgeredRootPublisher, PublishCancellation,
    PublishCutPoint, RootLedgerReceipt, RootLedgerReconciliation, SlotName,
};

use super::ReferenceDeployment;
use super::constants::{
    FAMILY_CALIBRATION_INVALIDATION, FAMILY_EVIDENCE_HOLD, FAMILY_RETENTION_POLICY,
    STAGE_APPEND_BATCH, STAGE_PUBLISH_ROOT, STAGE_STAGE_MANIFEST, STAGE_STAGE_OBJECTS,
    publish_cut_point_stage, reserved_family_entry_point,
};
use crate::adapter_replay::{NoReplayAdmission, ReplayAdmission, ReplayCx};
use crate::error::ReferenceError;

/// Handle to a staged manifest that has not yet been committed to authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedManifestHandle {
    /// Target publication slot.
    pub slot: SlotName,
    /// Staged object manifest.
    pub manifest: ObjectManifest,
    /// Computed manifest root.
    pub root: ContentDigest,
}

/// Cancellation probe bridging [`ReplayCx`] to [`PublishCancellation`].
///
/// The local publisher polls it at each pre-commit cut point. The context records that it reached
/// the cut point's registered stage, and a requested cancellation is drained and finalized before
/// the publisher is told to stop.
#[derive(Debug)]
pub struct ReplayCancellationBridge<'a, G: ReplayAdmission = NoReplayAdmission>(
    pub &'a ReplayCx<G>,
);

impl<G: ReplayAdmission> PublishCancellation for ReplayCancellationBridge<'_, G> {
    fn cancel_requested(&self, point: PublishCutPoint) -> bool {
        self.0.reach_stage(publish_cut_point_stage(point));
        if self.0.is_cancelled() {
            self.0.drain_and_finalize();
            true
        } else {
            false
        }
    }
}

fn delta_order_key(delta: &EvidenceDelta) -> (&str, &str, u64, &str) {
    (
        delta.family.as_str(),
        delta.object_id.as_str(),
        delta.new_generation,
        delta.delta_id.as_str(),
    )
}

impl ReferenceDeployment {
    /// Stages child payload bytes and the manifest for `slot` without making anything visible.
    ///
    /// Stage-only: every child is staged in the deployment spool and the manifest body is staged
    /// in the local publisher, but no root record is written and the ledger is untouched. The
    /// returned [`StagedManifestHandle`] becomes visible only through [`Self::publish_and_commit`],
    /// which publishes root-last and commits reachability to the canonical ledger.
    /// Repeated payloads share one content-addressed child; role-specific references remain in
    /// their owning records. The input-count limit applies before this deduplication.
    pub fn stage_and_publish(
        &mut self,
        slot: &SlotName,
        objects: &[&[u8]],
        cx: &ReplayCx<impl ReplayAdmission>,
    ) -> Result<StagedManifestHandle, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_STAGE_OBJECTS,
            });
        }

        if objects.len() > self.limits.manifest_children_max {
            return Err(ReferenceError::CapacityExceeded {
                limit: "manifest_children_max",
                maximum: self.limits.manifest_children_max as u64,
                actual: objects.len() as u64,
            });
        }

        let mut child_digests = Vec::with_capacity(objects.len());
        for obj in objects {
            if cx.is_cancelled() {
                cx.drain_and_finalize();
                return Err(ReferenceError::CancellationRequested {
                    stage: STAGE_STAGE_OBJECTS,
                });
            }
            if obj.len() as u64 > self.limits.spool_object_max_bytes {
                return Err(ReferenceError::CapacityExceeded {
                    limit: "spool_object_max_bytes",
                    maximum: self.limits.spool_object_max_bytes,
                    actual: obj.len() as u64,
                });
            }
            let digest = self.publisher.stage_object(obj)?;
            child_digests.push(digest);
        }

        cx.reach_stage(STAGE_STAGE_MANIFEST);
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_STAGE_MANIFEST,
            });
        }

        // A publication's closure names stored objects, not every semantic role using them.
        // Quiet frames can share source bytes and decode receipts with the reference frame.
        // Preserve every role in its record while presenting unique children to the strict
        // canonical manifest constructor; its duplicate-input validation remains unchanged.
        child_digests.sort_unstable();
        child_digests.dedup();
        let manifest = ObjectManifest::new(slot.as_str(), child_digests, None)?;
        let manifest_root = self.publisher.stage_manifest(slot, &manifest)?;

        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_PUBLISH_ROOT,
            });
        }

        Ok(StagedManifestHandle {
            slot: slot.clone(),
            manifest,
            root: manifest_root,
        })
    }

    /// Publishes a manifest into `slot` root-last and commits its reachability to the canonical ledger.
    ///
    /// `cx` is checked before any work and polled again at every pre-commit publication cut point
    /// (`after_children_verified`, `after_manifest_body`, `after_root_temp_write`). A cancellation
    /// there returns [`ReferenceError::CancellationRequested`] naming that stage, removes any
    /// temporary root record, and leaves the ledger unchanged. The rename is the commit point:
    /// cancellation is never honored after it, so the root becomes durable and is ledgered.
    pub fn publish_and_commit(
        &mut self,
        slot: &SlotName,
        manifest: &ObjectManifest,
        validity: CaptureInterval,
        cx: &ReplayCx<impl ReplayAdmission>,
    ) -> Result<RootLedgerReceipt, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_PUBLISH_ROOT,
            });
        }

        let bridge = ReplayCancellationBridge(cx);
        let injected = self.injected_ledger_crash.take();
        let mut ledgered = LedgeredRootPublisher::new(&mut self.publisher, &mut self.ledger);
        if let Some(point) = injected {
            ledgered.inject_crash_at(point);
        }
        let receipt = ledgered.publish_and_commit_cancellable(slot, manifest, validity, &bridge)?;
        Ok(receipt)
    }

    /// Arms a one-shot ledger-linkage crash for the next [`Self::publish_and_commit`].
    ///
    /// Fault-injection seam for the laboratory crash matrix (fss-2h5zq.15): it forwards to
    /// [`LedgeredRootPublisher::inject_crash_at`], so the call returns the linkage's
    /// `InjectedCrash` and poisons the local publisher exactly as that seam documents. It is
    /// in-process injection, not process death.
    #[doc(hidden)]
    pub fn inject_ledger_crash_at(&mut self, point: LedgerCutPoint) {
        self.injected_ledger_crash = Some(point);
    }

    /// Arms a one-shot failure after `phase` of the next authority-ledger journal append.
    ///
    /// Fault-injection seam for the laboratory crash matrix (fss-2h5zq.15): it forwards to
    /// [`fss_ledger::DurableReferenceLedger::fail_journal_after_phase`], so the append returns
    /// `AppendIndeterminate` with the bytes that phase left on disk. It is in-process injection,
    /// not process death or power loss.
    #[doc(hidden)]
    pub fn fail_ledger_append_after_phase(&mut self, phase: AppendPhase) {
        self.ledger.fail_journal_after_phase(phase);
    }

    /// Prepares and commits an authority batch to the canonical ledger, verifying child custody.
    ///
    /// The reserved families `event_revision` and `sensor_tamper_status` (use
    /// [`Self::publish_event`]) and `local_root_reachability` (use [`Self::publish_and_commit`])
    /// are refused with [`ReferenceError::ReservedDeltaFamily`] before any work. Hold families
    /// and their object namespace also require the guarded retention entry point.
    ///
    /// Idempotent by `batch_id`: when the ledger already holds this batch identity with identical
    /// deltas and children, returns the committed anchor without re-preparing deltas. If the batch
    /// identity exists with different content, refuses with [`DurableLedgerError::BatchIdConflict`].
    pub fn append_batch(
        &mut self,
        batch_id: BatchId,
        deltas: Vec<EvidenceDelta>,
        children: Vec<ContentDigest>,
        cx: &ReplayCx,
    ) -> Result<LedgerAnchor, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_APPEND_BATCH,
            });
        }

        // Reserved object identities stay guarded even when a caller changes the family.
        if deltas.iter().any(|delta| {
            delta
                .object_id
                .as_str()
                .starts_with(crate::review_media::delivery::DELIVERY_OBJECT_PREFIX)
        }) {
            return Err(ReferenceError::ReservedDeltaFamily {
                family: crate::review_media::delivery::FAMILY_REVIEW_DELIVERY_STARTED.to_owned(),
                entry_point: "review_media::delivery::begin_review_delivery/verify_review_delivery",
            });
        }
        if deltas.iter().any(|delta| {
            delta
                .object_id
                .as_str()
                .starts_with(crate::review_media::REVIEW_OBJECT_PREFIX)
        }) {
            return Err(ReferenceError::ReservedDeltaFamily {
                family: crate::review_media::FAMILY_REVIEW_MEDIA.to_owned(),
                entry_point: "review_media::commit_review_media/revoke_review_media",
            });
        }
        if deltas.iter().any(|delta| {
            delta.object_id.as_str() == crate::deployment_backup::RESTORE_FENCE_OBJECT_ID
        }) {
            return Err(ReferenceError::ReservedDeltaFamily {
                family: crate::deployment_backup::FAMILY_RESTORE_FENCE.to_owned(),
                entry_point: "deployment_backup::restore_backup",
            });
        }
        if deltas.iter().any(|delta| {
            delta
                .object_id
                .as_str()
                .starts_with(crate::discovery::retained_liveness::LIVENESS_OBJECT_PREFIX)
        }) {
            return Err(ReferenceError::ReservedDeltaFamily {
                family: crate::discovery::retained_liveness::FAMILY_SENSOR_LIVENESS.to_owned(),
                entry_point: "discovery::retained_liveness::retain_discovery_window",
            });
        }
        // Reserve the namespace too: changing family must not shadow an effective hold.
        if deltas.iter().any(|delta| {
            delta
                .object_id
                .as_str()
                .starts_with(crate::ingest::historical_health::HISTORICAL_HEALTH_OBJECT_PREFIX)
        }) {
            return Err(ReferenceError::ReservedDeltaFamily {
                family: crate::ingest::historical_health::FAMILY_HISTORICAL_HEALTH.to_owned(),
                entry_point: "ingest::historical_health::HistoricalHealthDiagnostic::retain",
            });
        }
        if deltas.iter().any(|delta| {
            delta
                .object_id
                .as_str()
                .starts_with(crate::deletion::holds::HOLD_OBJECT_PREFIX)
        }) {
            return Err(ReferenceError::ReservedDeltaFamily {
                family: FAMILY_EVIDENCE_HOLD.to_owned(),
                entry_point: "deletion::holds::commit_hold",
            });
        }
        // Reserved families are committed only by their guarded entry points; refused before
        // any custody work, preparation, or journal I/O.
        if deltas.iter().any(|delta| {
            delta
                .object_id
                .as_str()
                .starts_with(crate::deletion::retention::policy::POLICY_OBJECT_PREFIX)
        }) {
            return Err(ReferenceError::ReservedDeltaFamily {
                family: FAMILY_RETENTION_POLICY.to_owned(),
                entry_point: "deletion::retention::policy::commit_policy_change",
            });
        }
        if deltas.iter().any(|delta| {
            delta
                .object_id
                .as_str()
                .starts_with(crate::ingest::calibration_invalidation::INVALIDATION_OBJECT_PREFIX)
        }) {
            return Err(ReferenceError::ReservedDeltaFamily {
                family: FAMILY_CALIBRATION_INVALIDATION.to_owned(),
                entry_point: "ingest::calibration_invalidation::invalidate",
            });
        }
        if let Some((family, entry_point)) = deltas.iter().find_map(|delta| {
            reserved_family_entry_point(&delta.family).map(|entry| (delta.family.clone(), entry))
        }) {
            return Err(ReferenceError::ReservedDeltaFamily {
                family,
                entry_point,
            });
        }
        self.append_checked_batch(batch_id, deltas, children)
    }

    /// Commits a withdrawal only after the calibration owner has verified the exact adoption,
    /// owner approval and optional retained evidence. Ordinary appends cannot manufacture or
    /// replace a withdrawal, including by disguising its object namespace under another family.
    pub(crate) fn append_calibration_invalidation_batch(
        &mut self,
        batch_id: BatchId,
        deltas: Vec<EvidenceDelta>,
        children: Vec<ContentDigest>,
        cx: &ReplayCx,
    ) -> Result<LedgerAnchor, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_APPEND_BATCH,
            });
        }
        if deltas.len() != 1
            || deltas.iter().any(|delta| {
                delta.family != FAMILY_CALIBRATION_INVALIDATION
                    || !delta.object_id.as_str().starts_with(
                        crate::ingest::calibration_invalidation::INVALIDATION_OBJECT_PREFIX,
                    )
                    || delta.plane != Plane::Authority
                    || delta.prior_generation.is_some()
                    || delta.new_generation != 1
                    || delta.witness_digest.is_none()
                    || delta.operation_id.is_some()
            })
        {
            return Err(ReferenceError::InvalidSpec(
                "invalid calibration invalidation batch",
            ));
        }
        self.append_checked_batch(batch_id, deltas, children)
    }

    /// Commits one sensor liveness generation only after enrollment and metadata validation.
    /// Generic appends cannot manufacture liveness or shadow its sensor namespace.
    pub(crate) fn append_sensor_liveness_batch(
        &mut self,
        batch_id: BatchId,
        deltas: Vec<EvidenceDelta>,
        children: Vec<ContentDigest>,
        cx: &ReplayCx,
    ) -> Result<LedgerAnchor, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_APPEND_BATCH,
            });
        }
        if deltas.len() != 1
            || deltas.iter().any(|delta| {
                delta.family != crate::discovery::retained_liveness::FAMILY_SENSOR_LIVENESS
                    || !delta
                        .object_id
                        .as_str()
                        .starts_with(crate::discovery::retained_liveness::LIVENESS_OBJECT_PREFIX)
                    || delta.plane != Plane::Authority
                    || delta.new_generation == 0
                    || delta.prior_generation
                        != delta.new_generation.checked_sub(1).filter(|g| *g != 0)
                    || delta.witness_digest.is_none()
                    || delta.operation_id.is_some()
            })
        {
            return Err(ReferenceError::InvalidSpec("invalid sensor liveness batch"));
        }
        self.append_checked_batch(batch_id, deltas, children)
    }

    /// Crate-internal writer for one independently approved native historical diagnostic.
    /// Generic appends cannot manufacture the family or shadow its stable receipt namespace.
    pub(crate) fn append_historical_health_batch(
        &mut self,
        batch_id: BatchId,
        deltas: Vec<EvidenceDelta>,
        children: Vec<ContentDigest>,
        cx: &ReplayCx,
    ) -> Result<LedgerAnchor, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_APPEND_BATCH,
            });
        }
        if deltas.len() != 1
            || deltas.iter().any(|delta| {
                delta.family != crate::ingest::historical_health::FAMILY_HISTORICAL_HEALTH
                    || !delta.object_id.as_str().starts_with(
                        crate::ingest::historical_health::HISTORICAL_HEALTH_OBJECT_PREFIX,
                    )
                    || delta.plane != Plane::Authority
                    || delta.prior_generation.is_some()
                    || delta.new_generation != 1
                    || delta.witness_digest.is_none()
                    || delta.operation_id.is_some()
            })
        {
            return Err(ReferenceError::InvalidSpec(
                "invalid historical health batch",
            ));
        }
        self.append_checked_batch(batch_id, deltas, children)
    }

    /// Crate-internal writer for the exact transition validated by `evidence_export`.
    /// The export family is reserved so generic authority appends cannot synthesize a P5 export.
    pub(crate) fn append_evidence_export_batch(
        &mut self,
        batch_id: BatchId,
        deltas: Vec<EvidenceDelta>,
        children: Vec<ContentDigest>,
        cx: &ReplayCx,
    ) -> Result<LedgerAnchor, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_APPEND_BATCH,
            });
        }
        if deltas.len() != 1
            || deltas.iter().any(|delta| {
                delta.family != crate::evidence_export::FAMILY_EVIDENCE_EXPORT
                    || !delta
                        .object_id
                        .as_str()
                        .starts_with(crate::evidence_export::EXPORT_OBJECT_PREFIX)
                    || delta.plane != Plane::Authority
            })
        {
            return Err(ReferenceError::InvalidSpec("invalid evidence export batch"));
        }
        self.append_checked_batch(batch_id, deltas, children)
    }

    /// Guarded issuance/terminal withdrawal of a locally scoped retained review derivative.
    /// The lifecycle owner verifies actual source rendering, exact approval and custody first.
    pub(crate) fn append_review_media_batch(
        &mut self,
        batch_id: BatchId,
        deltas: Vec<EvidenceDelta>,
        children: Vec<ContentDigest>,
        cx: &ReplayCx,
    ) -> Result<LedgerAnchor, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_APPEND_BATCH,
            });
        }
        if deltas.len() != 1
            || deltas.iter().any(|delta| {
                let transition = match delta.family.as_str() {
                    crate::review_media::FAMILY_REVIEW_MEDIA => {
                        delta.prior_generation.is_none() && delta.new_generation == 1
                    }
                    crate::review_media::FAMILY_REVIEW_REVOCATION => {
                        delta.prior_generation == Some(1) && delta.new_generation == 2
                    }
                    _ => false,
                };
                !transition
                    || !delta
                        .object_id
                        .as_str()
                        .starts_with(crate::review_media::REVIEW_OBJECT_PREFIX)
                    || delta.plane != Plane::Authority
                    || delta.witness_digest.is_none()
                    || delta.operation_id.is_some()
            })
        {
            return Err(ReferenceError::InvalidSpec(
                "invalid review-media authority transition",
            ));
        }
        self.append_checked_batch(batch_id, deltas, children)
    }

    /// Guarded local delivery lifecycle, owned by actual review-media file readback.
    /// Generic appends cannot issue either family or shadow this object namespace.
    pub(crate) fn append_review_delivery_batch(
        &mut self,
        batch_id: BatchId,
        deltas: Vec<EvidenceDelta>,
        children: Vec<ContentDigest>,
        cx: &ReplayCx,
    ) -> Result<LedgerAnchor, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_APPEND_BATCH,
            });
        }
        if deltas.len() != 1
            || deltas.iter().any(|delta| {
                let transition = match delta.family.as_str() {
                    crate::review_media::delivery::FAMILY_REVIEW_DELIVERY_STARTED => {
                        delta.prior_generation.is_none() && delta.new_generation == 1
                    }
                    crate::review_media::delivery::FAMILY_REVIEW_DELIVERY_VERIFIED => {
                        delta.prior_generation == Some(1) && delta.new_generation == 2
                    }
                    _ => false,
                };
                !transition
                    || !delta
                        .object_id
                        .as_str()
                        .starts_with(crate::review_media::delivery::DELIVERY_OBJECT_PREFIX)
                    || delta.plane != Plane::Authority
                    || delta.witness_digest.is_none()
                    || delta.operation_id.is_none()
            })
        {
            return Err(ReferenceError::InvalidSpec(
                "invalid review-delivery authority transition",
            ));
        }
        self.append_checked_batch(batch_id, deltas, children)
    }

    /// Crate-internal writer for the exact transition validated by `deletion::holds`.
    /// No other family, object namespace, or mixed batch is admitted through this entry point.
    pub(crate) fn append_evidence_hold_batch(
        &mut self,
        batch_id: BatchId,
        deltas: Vec<EvidenceDelta>,
        children: Vec<ContentDigest>,
        cx: &ReplayCx,
    ) -> Result<LedgerAnchor, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_APPEND_BATCH,
            });
        }
        if deltas.len() != 1
            || deltas.iter().any(|delta| {
                delta.family != FAMILY_EVIDENCE_HOLD
                    || !delta
                        .object_id
                        .as_str()
                        .starts_with(crate::deletion::holds::HOLD_OBJECT_PREFIX)
                    || delta.plane != Plane::Authority
            })
        {
            return Err(ReferenceError::InvalidSpec("invalid evidence hold batch"));
        }
        self.append_checked_batch(batch_id, deltas, children)
    }

    /// Guarded writer for one exact policy revision validated by the retention policy owner.
    pub(crate) fn append_retention_policy_batch(
        &mut self,
        batch_id: BatchId,
        deltas: Vec<EvidenceDelta>,
        children: Vec<ContentDigest>,
        cx: &ReplayCx,
    ) -> Result<LedgerAnchor, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_APPEND_BATCH,
            });
        }
        if deltas.len() != 1
            || deltas.iter().any(|delta| {
                delta.family != FAMILY_RETENTION_POLICY
                    || delta.plane != Plane::Authority
                    || !delta
                        .object_id
                        .as_str()
                        .starts_with(crate::deletion::retention::policy::POLICY_OBJECT_PREFIX)
            })
        {
            return Err(ReferenceError::InvalidSpec(
                "invalid retention policy batch",
            ));
        }
        self.append_checked_batch(batch_id, deltas, children)
    }

    /// Crate-internal entry of the deletion-closure owner ([`crate::deletion`]): appends a batch
    /// whose deltas may carry only the deletion-reserved families (deletion record, tombstone,
    /// completion, root retraction), with every other check of [`Self::append_batch`]. Any other
    /// reserved family is still refused.
    pub(crate) fn append_deletion_batch(
        &mut self,
        batch_id: BatchId,
        deltas: Vec<EvidenceDelta>,
        children: Vec<ContentDigest>,
        cx: &ReplayCx,
    ) -> Result<LedgerAnchor, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_APPEND_BATCH,
            });
        }
        if let Some((family, entry_point)) = deltas.iter().find_map(|delta| {
            reserved_family_entry_point(&delta.family)
                .filter(|entry| *entry != "deletion::commit_deletion")
                .map(|entry| (delta.family.clone(), entry))
        }) {
            return Err(ReferenceError::ReservedDeltaFamily {
                family,
                entry_point,
            });
        }
        self.append_checked_batch(batch_id, deltas, children)
    }

    fn append_checked_batch(
        &mut self,
        batch_id: BatchId,
        deltas: Vec<EvidenceDelta>,
        children: Vec<ContentDigest>,
    ) -> Result<LedgerAnchor, ReferenceError> {
        if deltas.len() > self.limits.batch_entries_max {
            return Err(ReferenceError::CapacityExceeded {
                limit: "batch_entries_max",
                maximum: self.limits.batch_entries_max as u64,
                actual: deltas.len() as u64,
            });
        }
        if children.len() > self.limits.batch_entries_max {
            return Err(ReferenceError::CapacityExceeded {
                limit: "batch_entries_max",
                maximum: self.limits.batch_entries_max as u64,
                actual: children.len() as u64,
            });
        }

        let mut deltas = deltas;
        deltas.sort_by(|left, right| delta_order_key(left).cmp(&delta_order_key(right)));
        let mut children = children;
        children.sort_unstable();
        children.dedup();

        // Idempotency check: check if batch_id already exists in ledger history.
        if let Some(existing) = self
            .ledger
            .batches()
            .iter()
            .find(|batch| batch.batch_id == batch_id)
        {
            if existing.deltas == deltas && existing.children == children {
                return Ok(existing.new_anchor.clone());
            }
            let candidate_batch = EvidenceDeltaBatch {
                batch_id: batch_id.clone(),
                basis_anchor: existing.basis_anchor.clone(),
                new_anchor: existing.new_anchor.clone(),
                deltas: deltas.clone(),
                children: children.clone(),
                batch_digest: ContentDigest::sha256(b""),
            };
            let offered_digest = candidate_batch.computed_digest();
            return Err(DurableLedgerError::BatchIdConflict {
                batch_id: existing.batch_id.clone(),
                committed_sequence: existing.new_anchor.commit_sequence,
                committed_digest: existing.batch_digest,
                offered_digest,
            }
            .into());
        }

        // Bound the journal record before any custody work or preparation. `prepare_batch` derives
        // the successor anchor from the current one by changing only fixed-width fields (commit
        // sequence and state root), so a candidate that carries the current anchor as both basis
        // and successor encodes to exactly the length of the batch that would be appended.
        let current_anchor = self.ledger.current().anchor.clone();
        let mut candidate = EvidenceDeltaBatch {
            batch_id: batch_id.clone(),
            basis_anchor: current_anchor.clone(),
            new_anchor: current_anchor,
            deltas: deltas.clone(),
            children: children.clone(),
            batch_digest: ContentDigest::sha256(b""),
        };
        candidate.batch_digest = candidate.computed_digest();
        let encoded = fss_ledger::encode_batch(&candidate)
            .map_err(|e| ReferenceError::DurableLedger(Box::new(DurableLedgerError::Codec(e))))?;
        if encoded.len() > self.limits.journal_record_max_bytes as usize {
            return Err(ReferenceError::CapacityExceeded {
                limit: "journal_record_max_bytes",
                maximum: self.limits.journal_record_max_bytes as u64,
                actual: encoded.len() as u64,
            });
        }

        for child in &children {
            self.publisher.verify_object(*child)?;
        }
        for delta in &deltas {
            self.publisher.verify_object(delta.payload_digest)?;
            if let Some(witness) = delta.witness_digest {
                self.publisher.verify_object(witness)?;
            }
        }

        let mut auth = AuthorityPublisher::new(&self.publisher, &mut self.ledger);
        let batch = auth.prepare_batch(batch_id, deltas, children)?;
        let anchor = auth.append(batch)?;
        Ok(anchor)
    }

    /// Stages a single object payload into the spool and returns its content digest.
    pub fn stage_payload(&mut self, bytes: &[u8]) -> Result<ContentDigest, ReferenceError> {
        if bytes.len() as u64 > self.limits.spool_object_max_bytes {
            return Err(ReferenceError::CapacityExceeded {
                limit: "spool_object_max_bytes",
                maximum: self.limits.spool_object_max_bytes,
                actual: bytes.len() as u64,
            });
        }
        let digest = self.publisher.stage_object(bytes)?;
        Ok(digest)
    }

    /// Returns a borrow-scoped [`LedgeredRootPublisher`] over this deployment's publisher and ledger.
    pub fn ledgered_publisher<'a>(&'a mut self) -> LedgeredRootPublisher<'a> {
        LedgeredRootPublisher::new(&mut self.publisher, &mut self.ledger)
    }

    /// Classifies visible roots against ledger reachability claims.
    pub fn reconcile(&mut self) -> Result<RootLedgerReconciliation, ReferenceError> {
        let ledgered = LedgeredRootPublisher::new(&mut self.publisher, &mut self.ledger);
        Ok(ledgered.reconcile()?)
    }
}
