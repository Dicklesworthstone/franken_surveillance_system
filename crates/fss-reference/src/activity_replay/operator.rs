#![forbid(unsafe_code)]
//! Cold, read-only composition of retained activity, native custody and independent rederivation.
//!
//! The caller selects the source slots and original computation parameters. A conclusion cannot
//! select its own authority or silently hydrate the rest of the deployment. Complete committed
//! deletion history is checked before source reads. No deployment writer, lock, repair or effect
//! is opened. The final head comparison is an observation, not a lease on future availability.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

use fss_codec_mjpeg::DecodeBudget;
use fss_core::belief_verification::RetainedBeliefEvidence;
use fss_core::belief_verification::graph::{
    BeliefGraphFailure, BeliefGraphRequest, BeliefGraphUsage, verify_derived_belief_graph,
};
use fss_core::{
    ContentDigest, DerivedBelief, DigestAlgorithm, ObjectId, ObjectRevision, Plane, ReferenceLedger,
};
use fss_object::{ObjectManifest, SpoolIo};
use fss_publication::custody_audit::belief_snapshot::durable::{
    DurableBeliefError, DurableBeliefLimits,
};
use fss_publication::custody_audit::belief_snapshot::{
    CapturedBeliefCustody, capture_belief_custody,
};
use fss_publication::custody_audit::{CustodyRootBasis, LocalCustodyAudit};
use fss_publication::{
    ROOT_REACHABILITY_FAMILY, SlotName, read_verified_with_io, root_reachability_object_id,
    root_record_bytes,
};

use super::belief::{ActivityBeliefEngine, ActivityEvidenceBinding, ActivityEvidenceSet};
use super::{ActivityReplayLimits, ActivityReplayPlan};
use crate::ScalarExecCx;
use crate::agent_orient::{DeploymentHistory, OrientLimits};
use crate::deletion::belief::{
    BoundedCommittedDeletionBeliefAuthority, DeletionBeliefLimits, DeletionBeliefUsage,
};
use crate::executor_activity::{
    ExecutorModelResult, retention_batch, retention_deltas, retention_slot,
};

/// Small explicit source selection; no whole-deployment source expansion.
pub const MAX_ACTIVITY_SOURCE_SLOTS: usize = 8;

/// Independent allowances for history, deletion metadata, custody, graph copies and native work.
#[derive(Clone, Copy, Debug)]
pub struct ActivityVerificationLimits {
    /// Existing read-only deployment parser's per-file ceilings.
    pub history: OrientLimits,
    /// Complete deletion proof admission, including revoked aliases.
    pub deletion: DeletionBeliefLimits,
    /// Replay, captured custody and graph verification ceilings.
    pub verification: DurableBeliefLimits,
    /// Exact native metadata, input and decoded-frame ceilings.
    pub native: ActivityReplayLimits,
    /// Combined native JPEG work allowance; not wall-clock time.
    pub max_decode_work: u64,
}

impl Default for ActivityVerificationLimits {
    fn default() -> Self {
        Self {
            history: OrientLimits {
                max_journal_bytes: 1024 * 1024,
                ..OrientLimits::default()
            },
            deletion: DeletionBeliefLimits::default(),
            verification: DurableBeliefLimits::default(),
            native: ActivityReplayLimits::default(),
            max_decode_work: 20_000_000,
        }
    }
}

/// Explicit local operator request. This interface does not authenticate a remote principal or
/// apply an export privacy transform; possession of this request is not a source-read capability.
pub struct ActivityVerificationRequest<'a> {
    /// Existing deployment root. Missing roots are refused without creating anything.
    pub root: &'a Path,
    /// Independently expected deployment lineage.
    pub site: &'a str,
    /// Optional exact committed journal root, binding the complete ledger anchor and history.
    pub expected_ledger_root: Option<ContentDigest>,
    /// Retained `ExecutorModelResult` object, not a supplied statement or score.
    pub result: ContentDigest,
    /// Independently selected earlier source capsule; not inferred from the offered score.
    pub reference_capsule: ContentDigest,
    /// Authorized source slots, nonempty and strictly increasing. The deterministic result slot
    /// is added separately; source roles must still belong to these selected source closures.
    pub source_slots: &'a [SlotName],
    /// Original invocation parameters selected independently of the retained result.
    pub plan: ActivityReplayPlan,
}

/// No partial belief or source bytes are returned on any refusal.
#[derive(Debug)]
pub enum ActivityVerificationError {
    /// Invalid request, selection or retained role binding.
    Selection,
    /// Deployment read/replay failed or exceeded its existing intake bounds.
    History,
    /// Expected site or exact ledger-root pin differs.
    Anchor,
    /// The committed head or object namespace changed during the observation.
    AuthorityChanged,
    /// Complete deletion authority could not be established.
    Deletion(DurableBeliefError),
    /// Selected native custody was missing, corrupt, revoked, changed or over budget.
    Custody(fss_publication::custody_audit::belief_snapshot::CustodyCaptureError),
    /// Membership, bounded graph traversal or independent native derivation refused.
    Graph(BeliefGraphFailure),
    /// A logical history, graph-binding or input allowance was exhausted.
    Limit(&'static str),
    /// Native result, invocation or independently selected computation did not verify.
    Replay,
    /// Owner cancellation or deadline, with no successful report.
    Cancelled,
}

impl fmt::Display for ActivityVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selection => f.write_str("activity selection or retained role binding is invalid"),
            Self::History => f.write_str("committed deployment history is unreadable, invalid or beyond its read bounds"),
            Self::Anchor => f.write_str("activity deployment site or expected ledger root differs"),
            Self::AuthorityChanged => f.write_str("activity authority changed during verification"),
            Self::Deletion(error) => write!(f, "activity deletion authority: {error}"),
            Self::Custody(error) => write!(f, "activity {error}"),
            Self::Graph(error) => write!(f, "activity {error}"),
            Self::Limit(dimension) => write!(f, "activity {dimension} allowance exhausted"),
            Self::Replay => f.write_str("retained activity does not reproduce under the independently selected native computation"),
            Self::Cancelled => f.write_str("activity verification cancelled or deadline reached"),
        }
    }
}
impl std::error::Error for ActivityVerificationError {}
type Error = ActivityVerificationError;

/// A complete observation produced only after custody, authority membership and native replay.
/// It is not a transferable permission, calibrated physical claim or continuing custody lease.
#[derive(Debug)]
pub struct VerifiedActivityObservation {
    belief: DerivedBelief,
    result: ExecutorModelResult,
    ledger_root: ContentDigest,
    evidence: ActivityEvidenceSet,
    custody: LocalCustodyAudit,
    deletion: DeletionBeliefUsage,
    graph: BeliefGraphUsage,
    decode_work: u64,
}

impl VerifiedActivityObservation {
    /// Verified derived belief; its knowledge state remains Estimated and uncertainty [0,1].
    #[must_use]
    pub const fn belief(&self) -> &DerivedBelief {
        &self.belief
    }
    /// Exact retained result independently reproduced by native computation.
    #[must_use]
    pub const fn result(&self) -> &ExecutorModelResult {
        &self.result
    }
    /// Exact committed journal root observed before and after verification.
    #[must_use]
    pub const fn ledger_root(&self) -> ContentDigest {
        self.ledger_root
    }
    /// All eight role bindings, including any legitimate repeated content digests.
    #[must_use]
    pub const fn evidence(&self) -> &ActivityEvidenceSet {
        &self.evidence
    }
    /// Complete selected publication closure and physical read accounting.
    #[must_use]
    pub const fn custody(&self) -> &LocalCustodyAudit {
        &self.custody
    }
    /// Complete deletion-history verification usage.
    #[must_use]
    pub const fn deletion_usage(&self) -> DeletionBeliefUsage {
        self.deletion
    }
    /// Independent graph verification and derivation usage.
    #[must_use]
    pub const fn graph_usage(&self) -> BeliefGraphUsage {
        self.graph
    }
    /// Combined work actually consumed by both native JPEG decodes.
    #[must_use]
    pub const fn decode_work(&self) -> u64 {
        self.decode_work
    }
}

fn checkpoint(cancelled: &(impl Fn() -> bool + ?Sized), cx: &ScalarExecCx) -> Result<(), Error> {
    if cancelled() || cx.is_cancelled() {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
fn sha(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256 && digest.bytes() != [0; 32]
}
fn charge(used: &mut usize, n: usize, maximum: usize, field: &'static str) -> Result<(), Error> {
    *used = used
        .checked_add(n)
        .filter(|v| *v <= maximum)
        .ok_or(Error::Limit(field))?;
    Ok(())
}

// Bound the second core-ledger replay's retained snapshots and text before each clone. The initial
// DeploymentHistory read retains its own explicit journal byte ceiling and canonical codec bounds.
fn replay(
    history: &DeploymentHistory,
    limits: DurableBeliefLimits,
    cancelled: &(impl Fn() -> bool + ?Sized),
    cx: &ScalarExecCx,
) -> Result<ReferenceLedger, Error> {
    let batches = history.batches_through_head();
    if batches.len() > limits.max_batches {
        return Err(Error::Limit("history batches"));
    }
    let mut entries = 0;
    let mut snapshots = 0;
    let mut text = 0;
    let mut ledger = ReferenceLedger::new(history.site_lineage());
    for batch in batches {
        checkpoint(cancelled, cx)?;
        charge(
            &mut entries,
            batch.deltas.len(),
            limits.max_history_entries,
            "history entries",
        )?;
        charge(
            &mut entries,
            batch.children.len(),
            limits.max_history_entries,
            "history entries",
        )?;
        charge(
            &mut snapshots,
            ledger.current().objects.len(),
            limits.max_replay_snapshot_entries,
            "replay snapshots",
        )?;
        charge(
            &mut snapshots,
            batch.deltas.len(),
            limits.max_replay_snapshot_entries,
            "replay snapshots",
        )?;
        for value in [
            batch.batch_id.as_str(),
            batch.batch_id.as_str(),
            &batch.basis_anchor.site_lineage,
            &batch.new_anchor.site_lineage,
            &batch.new_anchor.site_lineage,
        ] {
            charge(
                &mut text,
                value.len(),
                limits.max_replay_text_bytes,
                "replay text",
            )?;
        }
        for (id, revision) in &ledger.current().objects {
            charge(
                &mut text,
                id.as_str().len() + revision.family.len(),
                limits.max_replay_text_bytes,
                "replay text",
            )?;
        }
        for delta in &batch.deltas {
            charge(
                &mut text,
                delta.delta_id.len() + 2 * delta.family.len() + 2 * delta.object_id.as_str().len(),
                limits.max_replay_text_bytes,
                "replay text",
            )?;
            if let Some(id) = &delta.operation_id {
                charge(
                    &mut text,
                    id.as_str().len(),
                    limits.max_replay_text_bytes,
                    "replay text",
                )?;
            }
        }
        ledger.append(batch.clone()).map_err(|_| Error::History)?;
    }
    Ok(ledger)
}

fn payload(
    custody: &CapturedBeliefCustody,
    digest: ContentDigest,
    limit: usize,
) -> Result<Vec<u8>, Error> {
    custody
        .read_belief_evidence(digest, limit)
        .map_err(|_| Error::Selection)
}

// Select roles through exact captured manifest edges. The core verifier independently establishes
// their ancestry again before native replay; this preliminary lookup never creates a proof.
fn source_bindings(
    custody: &CapturedBeliefCustody,
    selected: &[(SlotName, ObjectId, ObjectRevision)],
    source_slots: &[SlotName],
    limits: DurableBeliefLimits,
    cancelled: &(impl Fn() -> bool + ?Sized),
    cx: &ScalarExecCx,
) -> Result<BTreeMap<ContentDigest, ActivityEvidenceBinding>, Error> {
    let graph: BTreeMap<_, _> = custody
        .audit()
        .objects()
        .iter()
        .map(|row| (row.digest, row))
        .collect();
    let mut bindings = BTreeMap::new();
    let mut visits = 0;
    let mut edges = 0;
    for (slot, id, revision) in selected {
        if source_slots.binary_search(slot).is_err() {
            continue;
        }
        let mut pending = vec![revision.payload_digest];
        let mut seen = BTreeSet::new();
        while let Some(digest) = pending.pop() {
            checkpoint(cancelled, cx)?;
            if !seen.insert(digest) {
                continue;
            }
            charge(
                &mut visits,
                1,
                limits.graph.max_visits,
                "role binding visits",
            )?;
            let row = graph.get(&digest).ok_or(Error::Selection)?;
            charge(
                &mut edges,
                row.children.len(),
                limits.graph.max_edge_visits,
                "role binding edges",
            )?;
            pending.extend(row.children.iter().copied());
            bindings
                .entry(digest)
                .or_insert_with(|| ActivityEvidenceBinding {
                    digest,
                    authority: id.clone(),
                    revision: revision.clone(),
                });
        }
    }
    Ok(bindings)
}

/// Verify a retained result from a cold deployment without opening any mutating owner.
///
/// The selected source closures are captured in full, including unused siblings. The existing
/// canonical deletion owner checks all committed plans/completions before any source hydration.
/// A result is returned only after native JPEG decode and scalar inference reproduce both the
/// complete invocation receipt and result bytes, and a second history read matches the first.
/// Cancellation is cooperative; bounded filesystem calls and native replay are not preempted.
pub fn verify_retained_activity<C: Fn() -> bool + Sync>(
    request: ActivityVerificationRequest<'_>,
    io: &dyn SpoolIo,
    limits: ActivityVerificationLimits,
    cx: &ScalarExecCx,
    cancelled: &C,
) -> Result<VerifiedActivityObservation, Error> {
    checkpoint(cancelled, cx)?;
    if !sha(request.result)
        || !sha(request.reference_capsule)
        || request.expected_ledger_root.is_some_and(|d| !sha(d))
        || request.source_slots.is_empty()
        || request.source_slots.len() > MAX_ACTIVITY_SOURCE_SLOTS
        || !request.source_slots.windows(2).all(|p| p[0] < p[1])
    {
        return Err(Error::Selection);
    }
    let history =
        DeploymentHistory::read(request.root, &limits.history).map_err(|_| Error::History)?;
    checkpoint(cancelled, cx)?;
    let head = history.head();
    let roots = history.roots_at(head).ok_or(Error::History)?;
    if history.site_lineage() != request.site
        || request
            .expected_ledger_root
            .is_some_and(|pin| pin != roots.1)
    {
        return Err(Error::Anchor);
    }
    let ledger = replay(&history, limits.verification, cancelled, cx)?;
    if ledger.current().anchor != roots.0 {
        return Err(Error::History);
    }
    let result_slot = retention_slot(request.result).map_err(|_| Error::Selection)?;
    if request.source_slots.binary_search(&result_slot).is_ok() {
        return Err(Error::Selection);
    }
    let mut slots = request.source_slots.to_vec();
    slots.push(result_slot.clone());
    slots.sort();
    let deletion = BoundedCommittedDeletionBeliefAuthority::new(limits.deletion, cancelled);
    let denied = deletion
        .verified_denials_from_batches(history.batches_through_head(), &slots, |digest, maximum| {
            read_verified_with_io(
                history.replay_objects_root(),
                digest,
                maximum.min(limits.history.max_object_bytes),
                io,
            )
            .map_err(|_| DurableBeliefError::DeletionAuthorityInvalid)
        })
        .map_err(Error::Deletion)?;
    checkpoint(cancelled, cx)?;
    let mut selected = Vec::with_capacity(slots.len());
    let mut selected_roots = BTreeSet::new();
    for slot in slots {
        let id = root_reachability_object_id(&slot).map_err(|_| Error::Selection)?;
        let revision = ledger
            .current()
            .objects
            .get(&id)
            .ok_or(Error::Selection)?
            .clone();
        if revision.family != ROOT_REACHABILITY_FAMILY
            || revision.plane != Plane::Authority
            || revision.generation != 1
            || !sha(revision.payload_digest)
        {
            return Err(Error::Selection);
        }
        selected_roots.insert(revision.payload_digest);
        selected.push((slot, id, revision));
    }
    let custody = capture_belief_custody(
        io,
        history.replay_objects_root(),
        &selected_roots.into_iter().collect::<Vec<_>>(),
        &denied,
        limits.verification.custody,
        cancelled,
        CustodyRootBasis::LocalPublicationRecords,
        limits.verification.max_retained_bytes,
    )
    .map_err(Error::Custody)?;
    for (slot, _, revision) in &selected {
        let bytes = payload(
            &custody,
            revision.payload_digest,
            limits.verification.custody.max_object_bytes,
        )?;
        let manifest =
            ObjectManifest::from_canonical_bytes(&bytes).map_err(|_| Error::Selection)?;
        let count = manifest.children().len();
        let record = root_record_bytes(slot, revision.payload_digest, count)
            .map_err(|_| Error::Selection)?;
        if !custody.matches_publication_record(
            slot,
            revision.payload_digest,
            count as u64,
            ContentDigest::sha256(&record),
        ) {
            return Err(Error::Selection);
        }
    }
    let result = ExecutorModelResult::decode_canonical(&payload(
        &custody,
        request.result,
        limits.native.max_metadata_bytes,
    )?)
    .map_err(|_| Error::Selection)?;
    let (_, result_id, result_revision) = selected
        .iter()
        .find(|(slot, _, _)| slot == &result_slot)
        .ok_or(Error::Selection)?;
    let mut children = vec![request.result, result.invocation_receipt_object];
    children.sort_unstable();
    children.dedup();
    let manifest =
        ObjectManifest::new(result_slot.as_str(), children, None).map_err(|_| Error::Selection)?;
    if result_revision.payload_digest != manifest.root() {
        return Err(Error::Selection);
    }
    let batch_id = retention_batch(request.result).map_err(|_| Error::Selection)?;
    let batch = ledger
        .batches()
        .iter()
        .find(|b| b.batch_id == batch_id)
        .ok_or(Error::Selection)?;
    let validity = batch.deltas.first().ok_or(Error::Selection)?.validity;
    let deltas = retention_deltas(
        request.result,
        result.invocation_receipt_object,
        manifest.root(),
        validity,
    )
    .map_err(|_| Error::Selection)?;
    let mut children = manifest.children().to_vec();
    children.push(manifest.root());
    children.sort_unstable();
    children.dedup();
    if batch.deltas != deltas || batch.children != children {
        return Err(Error::Selection);
    }
    for delta in &deltas {
        let current = ledger
            .current()
            .objects
            .get(&delta.object_id)
            .ok_or(Error::Selection)?;
        if current
            != &(ObjectRevision {
                generation: delta.new_generation,
                family: delta.family.clone(),
                plane: delta.plane,
                payload_digest: delta.payload_digest,
                validity: delta.validity,
            })
        {
            return Err(Error::Selection);
        }
    }
    let bindings = source_bindings(
        &custody,
        &selected,
        request.source_slots,
        limits.verification,
        cancelled,
        cx,
    )?;
    let source = |digest| bindings.get(&digest).cloned().ok_or(Error::Selection);
    let result_binding = |digest| ActivityEvidenceBinding {
        digest,
        authority: result_id.clone(),
        revision: result_revision.clone(),
    };
    let evidence = ActivityEvidenceSet {
        result: result_binding(request.result),
        invocation: result_binding(result.invocation_receipt_object),
        frame_source: source(result.input_capture_root)?,
        reference_source: source(result.reference_capture_root)?,
        frame_capsule: source(result.capsule_digest)?,
        reference_capsule: source(request.reference_capsule)?,
        frame_decode: source(result.decode_receipt_digest)?,
        reference_decode: source(result.reference_decode_receipt_digest)?,
    };
    let engine = ActivityBeliefEngine::load_committed(
        request.plan,
        evidence.clone(),
        limits.native,
        DecodeBudget::new(limits.max_decode_work),
        cx,
    )
    .map_err(|_| Error::Replay)?;
    let offered = engine.offer(&result, &roots.0).map_err(|_| Error::Replay)?;
    let mut authority: Vec<_> = selected.iter().map(|(_, id, _)| id.clone()).collect();
    authority.sort();
    let verified = verify_derived_belief_graph(
        &offered,
        &ledger,
        &custody,
        &engine,
        BeliefGraphRequest {
            authority_objects: &authority,
            limits: limits.verification.graph,
            cancelled,
        },
    )
    .map_err(Error::Graph)?;
    let belief = verified.proof().belief().clone();
    let graph = verified.usage();
    checkpoint(cancelled, cx)?;
    let after = DeploymentHistory::read(request.root, &limits.history)
        .map_err(|_| Error::AuthorityChanged)?;
    checkpoint(cancelled, cx)?;
    if after.site_lineage() != request.site
        || after.head() != head
        || after.roots_at(head).as_ref() != Some(&roots)
        || after.replay_objects_root() != history.replay_objects_root()
    {
        return Err(Error::AuthorityChanged);
    }
    Ok(VerifiedActivityObservation {
        belief,
        result,
        ledger_root: roots.1,
        evidence,
        custody: custody.audit().clone(),
        deletion: deletion.usage(),
        graph,
        decode_work: engine.decode_work_used(),
    })
}
