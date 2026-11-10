#![forbid(unsafe_code)]
//! Root-last, ledgered custody of an explicitly unknown-time restart boundary.

use asupersync::Cx;
use fss_core::{
    BudgetVector, CanonicalDecoder, CanonicalEncoder, CaptureInterval, ContentDigest,
    DigestAlgorithm, RuntimeGrant, TimestampNs,
};
use fss_geometry::WorkBudget;
use fss_object::ObjectManifest;
use fss_publication::{
    PublishCancellation, PublishCutPoint, RootLedgerReceipt, RootLedgerState, SlotName,
};
use fss_runtime::{
    effect_journal::{EffectJournalPin, EffectJournalStore, PinRetainedEffectJournal},
    execution::TaskCx,
};

use super::{Created, MeteredClock, RestartBoundary, Resumed, archive};
use crate::{ReferenceDeployment, ReplayCx};

const DOMAIN: &str = "fss.unifi_restart_boundary.v1";
const KIND: &str = "unifi_restart_boundary_v1";
const MAX_BYTES: usize = 2048;
const MAX_BATCHES: usize = 65_536;

/// Exact candidate to retain independently before attempting publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pin {
    /// Canonical root of the boundary graph.
    pub root: ContentDigest,
    /// Identity of the A/V retention decision, not an authorization.
    pub retention: ContentDigest,
}

/// Exact immutable boundary candidate. Preparing it performs no I/O.
#[must_use = "retain the pin and publish or discard the candidate"]
pub struct Prepared {
    boundary: RestartBoundary,
    payload: Vec<u8>,
    manifest: ObjectManifest,
    slot: SlotName,
    pin: Pin,
}
impl Prepared {
    /// Candidate root and retention identity; this is not a receipt.
    pub fn pin(&self) -> Pin {
        self.pin
    }
    /// Caller-bound claims, with no physical-time or coverage assertion.
    pub fn boundary(&self) -> RestartBoundary {
        self.boundary
    }
}

/// A refusal never authorizes another connection or a changed candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The candidate does not match the recovered owner or its limits.
    Candidate,
    /// Task, cancellation, clock, or work admission refused.
    Admission,
    /// Current read or original-retention policy denied the exact root.
    Denied,
    /// Staging failed; some unreferenced payload may exist.
    Stage,
    /// Publication may have taken effect; inspect the same pin before retry.
    PublicationIndeterminate,
    /// The exact root and ledger claim are not both verified.
    NotLedgered,
    /// The retained graph or its unknown-time ledger marker differs.
    Mismatch,
    /// The independently retained boundary-custody history is absent or differs.
    Custody,
    /// A custody append may have succeeded; reopen its exact history before retry.
    CustodyIndeterminate,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UniFi restart boundary refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Refusal to release session owners; the exact owner remains recoverable.
#[must_use = "inspect or recover the returned recording owners"]
pub struct Refusal {
    /// Why the candidate was not admitted.
    pub reason: Error,
    /// Original archive owners and exact connection boundary.
    pub resumed: Resumed,
}
impl std::fmt::Debug for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Refusal")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

/// Reconstruct a candidate from previously retained claims. This creates no
/// publication, permission, camera identity or physical-time evidence.
pub fn prepare(boundary: RestartBoundary) -> Result<Prepared, Error> {
    if boundary.previous.connection == 0
        || boundary.previous.generation == 0
        || (boundary.next.generation, boundary.next.connection)
            <= (boundary.previous.generation, boundary.previous.connection)
        || boundary.next.connection == 0
        || [
            boundary.camera_claim,
            boundary.source_root.root,
            boundary.source_root.retention,
            boundary.av_root.root,
            boundary.av_root.retention,
        ]
        .iter()
        .any(|d| {
            d.algorithm() != DigestAlgorithm::Sha256 || d.is_laboratory() || d.bytes() == [0; 32]
        })
    {
        return Err(Error::Candidate);
    }
    let mut e = CanonicalEncoder::new();
    e.text(DOMAIN);
    e.digest(boundary.camera_claim);
    e.u64(boundary.previous.connection);
    e.u64(boundary.previous.generation);
    e.u64(boundary.next.connection);
    e.u64(boundary.next.generation);
    e.digest(boundary.source_root.root);
    e.digest(boundary.source_root.retention);
    e.digest(boundary.av_root.root);
    e.digest(boundary.av_root.retention);
    // These tags encode unknown capture bounds and unknown continuity, not a gap duration.
    e.bool(false);
    e.bool(false);
    let payload = e.finish_checked().map_err(|_| Error::Candidate)?;
    if payload.len() > MAX_BYTES {
        return Err(Error::Candidate);
    }
    let manifest = ObjectManifest::new(KIND, [], Some(ContentDigest::sha256(&payload)))
        .map_err(|_| Error::Candidate)?;
    let pin = Pin {
        root: manifest.root(),
        retention: boundary.av_root.retention,
    };
    let hex: String = pin
        .root
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let slot = SlotName::parse(&format!("ufrb1-{hex}")).map_err(|_| Error::Candidate)?;
    Ok(Prepared {
        boundary,
        payload,
        manifest,
        slot,
        pin,
    })
}

fn decode(bytes: &[u8]) -> Result<Prepared, Error> {
    if bytes.len() > MAX_BYTES {
        return Err(Error::Candidate);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text().map_err(|_| Error::Candidate)? != DOMAIN {
        return Err(Error::Candidate);
    }
    let camera_claim = d.digest().map_err(|_| Error::Candidate)?;
    let previous = fss_container::flv_avc::SourceKey {
        connection: d.u64().map_err(|_| Error::Candidate)?,
        generation: d.u64().map_err(|_| Error::Candidate)?,
    };
    let next = fss_container::flv_avc::SourceKey {
        connection: d.u64().map_err(|_| Error::Candidate)?,
        generation: d.u64().map_err(|_| Error::Candidate)?,
    };
    let source_root = archive::UnknownTimePin {
        root: d.digest().map_err(|_| Error::Candidate)?,
        retention: d.digest().map_err(|_| Error::Candidate)?,
    };
    let av_root = archive::UnknownTimePin {
        root: d.digest().map_err(|_| Error::Candidate)?,
        retention: d.digest().map_err(|_| Error::Candidate)?,
    };
    if d.bool().map_err(|_| Error::Candidate)? || d.bool().map_err(|_| Error::Candidate)? {
        return Err(Error::Candidate);
    }
    d.ensure_finished().map_err(|_| Error::Candidate)?;
    let plan = prepare(RestartBoundary {
        camera_claim,
        previous,
        next,
        source_root,
        av_root,
    })?;
    if plan.payload != bytes {
        return Err(Error::Candidate);
    }
    Ok(plan)
}

/// One exact boundary retained in a separately pinned custody journal.
/// The caller establishes the actual storage and failure-domain separation.
#[must_use = "use or explicitly recover the retained boundary custody"]
pub struct Custody {
    store: PinRetainedEffectJournal,
    plan: Prepared,
    head: EffectJournalPin,
    resource: String,
    replay: ReplayCx,
}
impl Custody {
    /// Persist one candidate before publication. Any ambiguous append must be
    /// recovered from the same journal and its separately retained head.
    pub fn create<'a, 'task>(
        mut store: PinRetainedEffectJournal,
        plan: &Prepared,
        resource: String,
        replay: ReplayCx,
        task: &'a TaskCx<'task>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'task>,
    ) -> Result<Self, Error> {
        custody_admit(&resource, &replay, task, cx, clock)?;
        if store.head().is_some() || !store.records().is_empty() {
            return Err(Error::Custody);
        }
        store
            .reserve_capacity(1, MAX_BYTES)
            .map_err(|_| Error::Custody)?;
        custody_admit(&resource, &replay, task, cx, clock)?;
        let head = store
            .append(None, &plan.payload)
            .map_err(|_| Error::CustodyIndeterminate)?;
        if store
            .verify_retained_head()
            .map_err(|_| Error::CustodyIndeterminate)?
            != head
            || store.records().len() != 1
            || store.records()[0] != plan.payload
        {
            return Err(Error::CustodyIndeterminate);
        }
        Ok(Self {
            store,
            plan: decode(&plan.payload)?,
            head,
            resource,
            replay,
        })
    }

    /// Reopen exactly one canonical boundary from a journal whose head was
    /// independently retained and verified by `for_reconciliation`.
    pub fn reopen<'a, 'task>(
        mut store: PinRetainedEffectJournal,
        resource: String,
        replay: ReplayCx,
        task: &'a TaskCx<'task>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'task>,
    ) -> Result<Self, Error> {
        custody_admit(&resource, &replay, task, cx, clock)?;
        let head = store.verify_retained_head().map_err(|_| Error::Custody)?;
        if head.sequence != 1 || store.records().len() != 1 {
            return Err(Error::Custody);
        }
        let plan = decode(&store.records()[0]).map_err(|_| Error::Custody)?;
        Ok(Self {
            store,
            plan,
            head,
            resource,
            replay,
        })
    }

    /// Recover the exact candidate, without granting publication authority.
    pub fn plan(&self) -> &Prepared {
        &self.plan
    }
    /// Journal head retained by the caller-selected separate custodian.
    pub fn head(&self) -> EffectJournalPin {
        self.head
    }

    fn check<'a, 'task>(
        &mut self,
        plan: &Prepared,
        task: &'a TaskCx<'task>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'task>,
    ) -> Result<(), Error> {
        custody_admit(&self.resource, &self.replay, task, cx, clock)?;
        if self.plan.pin != plan.pin
            || self.plan.boundary != plan.boundary
            || self.plan.payload != plan.payload
            || self
                .store
                .verify_retained_head()
                .map_err(|_| Error::Custody)?
                != self.head
            || self.store.records().len() != 1
            || self.store.records()[0] != plan.payload
        {
            return Err(Error::Custody);
        }
        Ok(())
    }
}

fn custody_admit<'a, 'task>(
    resource: &str,
    replay: &ReplayCx,
    task: &'a TaskCx<'task>,
    cx: &'a Cx,
    clock: MeteredClock<'a, 'task>,
) -> Result<(), Error> {
    let path = std::path::Path::new(resource);
    if !path.is_absolute() || !path.starts_with(replay.root_dir()) || !clock.matches(task, cx) {
        return Err(Error::Admission);
    }
    task.checkpoint_for(
        RuntimeGrant::ObjectStage,
        resource,
        clock.now().map_err(|_| Error::Admission)?,
        &BudgetVector::ZERO,
    )
    .map_err(|_| Error::Admission)?;
    replay
        .checkpoint("unifi-restart-boundary-custody")
        .map_err(|_| Error::Admission)
}

struct Gate<'a, 'task> {
    task: &'a TaskCx<'task>,
    cx: &'a Cx,
    clock: MeteredClock<'a, 'task>,
    replay: &'a ReplayCx,
    resource: &'a str,
    pin: Pin,
    read: &'a dyn archive::ReadAuthority,
    retain: &'a dyn archive::RetainAuthority,
}
impl Gate<'_, '_> {
    fn check(&self) -> Result<(), Error> {
        if !self.clock.matches(self.task, self.cx) {
            return Err(Error::Admission);
        }
        for grant in [
            RuntimeGrant::ObjectStage,
            RuntimeGrant::ObjectPublish,
            RuntimeGrant::ReadMedia,
        ] {
            self.task
                .checkpoint_for(
                    grant,
                    self.resource,
                    self.clock.now().map_err(|_| Error::Admission)?,
                    &BudgetVector::ZERO,
                )
                .map_err(|_| Error::Admission)?;
        }
        self.replay
            .checkpoint("unifi-restart-boundary")
            .map_err(|_| Error::Admission)?;
        if !self.read.permits(self.pin.retention, self.pin.root)
            || !self.retain.permits(self.pin.retention, self.pin.root)
        {
            return Err(Error::Denied);
        }
        Ok(())
    }
}
impl PublishCancellation for Gate<'_, '_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.check().is_err()
    }
}

fn unknown_validity() -> CaptureInterval {
    CaptureInterval {
        earliest: TimestampNs::MIN,
        latest: TimestampNs::MAX,
    }
}

impl Resumed {
    /// Prepare a deterministic, unknown-time boundary graph without I/O.
    pub fn prepare_boundary(&self) -> Result<Prepared, Error> {
        prepare(self.boundary)
    }

    /// Publish the exact boundary root-last into the A/V deployment's canonical ledger.
    /// An error after publication begins may be indeterminate; retain the same
    /// candidate and inspect it rather than inventing a new boundary.
    pub fn publish_boundary<'a, 'task>(
        &mut self,
        plan: &Prepared,
        custody: &mut Custody,
        task: &'a TaskCx<'task>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'task>,
        read: &dyn archive::ReadAuthority,
        work: &mut WorkBudget<'_>,
    ) -> Result<RootLedgerReceipt, Error> {
        if plan.boundary != self.boundary {
            return Err(Error::Candidate);
        }
        custody.check(plan, task, cx, clock)?;
        let av = &mut *self.owners.av;
        let resource = av
            .deployment
            .root()
            .to_str()
            .ok_or(Error::Candidate)?
            .to_owned();
        let gate = Gate {
            task,
            cx,
            clock,
            replay: &av.replay,
            resource: &resource,
            pin: plan.pin,
            read,
            retain: av.authority.as_ref(),
        };
        gate.check()?;
        work.charge(
            av.deployment.publisher().limits().max_tombstones as u64
                + 1
                + plan.payload.len() as u64 * 3,
        )
        .map_err(|_| Error::Admission)?;
        if av
            .deployment
            .publisher()
            .tombstones()
            .any(|d| *d == plan.pin.root || *d == ContentDigest::sha256(&plan.payload))
        {
            return Err(Error::Denied);
        }
        if av
            .deployment
            .stage_payload(&plan.payload)
            .map_err(|_| Error::Stage)?
            != ContentDigest::sha256(&plan.payload)
        {
            return Err(Error::Stage);
        }
        gate.check()?;
        let receipt = av
            .deployment
            .ledgered_publisher()
            .publish_and_commit_cancellable(&plan.slot, &plan.manifest, unknown_validity(), &gate)
            .map_err(|_| Error::PublicationIndeterminate)?;
        if receipt.root != plan.pin.root || receipt.slot != plan.slot {
            return Err(Error::PublicationIndeterminate);
        }
        Ok(receipt)
    }

    /// Verify the exact root, contents, canonical ledger claim and current
    /// authority before releasing the new session owners. A refusal preserves
    /// the owners; the caller retains the same candidate for reconciliation.
    pub fn into_owners<'a, 'task>(
        mut self,
        plan: &Prepared,
        custody: &mut Custody,
        task: &'a TaskCx<'task>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'task>,
        read: &dyn archive::ReadAuthority,
        work: &mut WorkBudget<'_>,
    ) -> Result<Created, Refusal> {
        if plan.boundary != self.boundary {
            return Err(Refusal {
                reason: Error::Candidate,
                resumed: self,
            });
        }
        if let Err(reason) = custody.check(plan, task, cx, clock) {
            return Err(Refusal {
                reason,
                resumed: self,
            });
        }
        let av = &mut *self.owners.av;
        match verify_retained(
            &mut av.deployment,
            &av.replay,
            av.authority.as_ref(),
            plan,
            task,
            cx,
            clock,
            read,
            work,
        ) {
            Ok(()) => Ok(self.owners),
            Err(reason) => Err(Refusal {
                reason,
                resumed: self,
            }),
        }
    }
}

/// Reverify an exact selected boundary against an existing deployment. The
/// candidate and any independently retained pin remain caller obligations;
/// this is not a latest-head, authentication, or automatic-resume proof.
pub fn verify_retained<'a, 'task>(
    deployment: &mut ReferenceDeployment,
    replay: &ReplayCx,
    retain: &dyn archive::RetainAuthority,
    plan: &Prepared,
    task: &'a TaskCx<'task>,
    cx: &'a Cx,
    clock: MeteredClock<'a, 'task>,
    read: &dyn archive::ReadAuthority,
    work: &mut WorkBudget<'_>,
) -> Result<(), Error> {
    let resource = deployment
        .root()
        .to_str()
        .ok_or(Error::Candidate)?
        .to_owned();
    let gate = Gate {
        task,
        cx,
        clock,
        replay,
        resource: &resource,
        pin: plan.pin,
        read,
        retain,
    };
    gate.check()?;
    let state = deployment
        .ledgered_publisher()
        .state(&plan.slot)
        .map_err(|_| Error::NotLedgered)?;
    let batch_id = match state {
        RootLedgerState::Ledgered { root, batch_id, .. } if root == plan.pin.root => batch_id,
        _ => return Err(Error::NotLedgered),
    };
    let object =
        fss_publication::root_reachability_object_id(&plan.slot).map_err(|_| Error::Mismatch)?;
    let mut found = false;
    for (index, batch) in deployment.ledger().batches().iter().enumerate() {
        if index >= MAX_BATCHES {
            return Err(Error::Admission);
        }
        work.charge(1 + batch.deltas.len() as u64)
            .map_err(|_| Error::Admission)?;
        if batch.batch_id != batch_id {
            continue;
        }
        let mut deltas = batch
            .deltas
            .iter()
            .filter(|delta| delta.object_id == object);
        let delta = deltas.next().ok_or(Error::Mismatch)?;
        if deltas.next().is_some()
            || delta.family != fss_publication::ROOT_REACHABILITY_FAMILY
            || delta.payload_digest != plan.pin.root
            || delta.validity != unknown_validity()
        {
            return Err(Error::Mismatch);
        }
        found = true;
        break;
    }
    if !found {
        return Err(Error::Mismatch);
    }
    work.charge(deployment.publisher().limits().max_tombstones as u64 + 1)
        .map_err(|_| Error::Admission)?;
    let metadata = ContentDigest::sha256(&plan.payload);
    if deployment
        .publisher()
        .tombstones()
        .any(|digest| *digest == plan.pin.root || *digest == metadata)
    {
        return Err(Error::Denied);
    }
    gate.check()?;
    let root = deployment
        .publisher()
        .spool()
        .read_bounded(plan.pin.root, MAX_BYTES)
        .map_err(|_| Error::Mismatch)?;
    let manifest = ObjectManifest::from_canonical_bytes(&root).map_err(|_| Error::Mismatch)?;
    if manifest != plan.manifest || manifest.root() != plan.pin.root {
        return Err(Error::Mismatch);
    }
    let payload = deployment
        .publisher()
        .spool()
        .read_bounded(metadata, MAX_BYTES)
        .map_err(|_| Error::Mismatch)?;
    if payload != plan.payload || ContentDigest::sha256(&payload) != metadata {
        return Err(Error::Mismatch);
    }
    gate.check()?;
    Ok(())
}
