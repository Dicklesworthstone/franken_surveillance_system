#![forbid(unsafe_code)]
//! Independently retained generation reservations. These synchronous calls
//! perform storage I/O and must run on a drained, region-owned blocking worker.
//! They do not prove physical custody independence or reconcile a created store.

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_geometry::{GeometryError, WorkBudget};
use fss_object::effect_journal::{FileEffectJournal, FileTrustedRootPinRetainer};
use fss_runtime::effect_journal::{
    EffectJournalPin, EffectJournalStore, EffectPersistenceError, EffectPinRetainer,
    PinRetainedEffectJournal,
};

use super::{Error as PlanError, Identity, Plan, Worker};
use crate::ReplayCx;

const DOMAIN: &str = "fss.unifi-direct.generation-reservation.v1";
const SCOPE_DOMAIN: &str = "fss.unifi-direct.generation-plan-scope.v1";
const ID_DOMAIN: &str = "fss.unifi-direct.generation-identity.v1";
const MAX_RECORD_BYTES: usize = 256;

/// Failure before returning a reserved creator. Storage errors may be ambiguous.
#[derive(Debug)]
pub enum ReservationError {
    /// Invalid configuration, history, scope, or generation order.
    Invalid,
    /// Caller authority or cancellation checkpoint failed.
    Cancelled,
    /// An earlier failure requires cold reconciliation.
    Fenced,
    /// An earlier reservation has not been explicitly reconciled.
    ReconciliationRequired,
    /// The bounded in-memory plan refused the operation.
    Plan(PlanError),
    /// Storage or independent pin custody refused or became uncertain.
    Storage(EffectPersistenceError),
}

/// Binding refusal retains the plan and the original journal owner.
#[must_use = "inspect or cold-reconcile the plan and retained journal"]
pub struct BindRefusal {
    /// Reason for refusal.
    pub reason: ReservationError,
    /// The original unstarted in-memory plan.
    pub plan: Plan,
    /// The exact retained journal, which may require a cold reopen.
    pub journal: PinRetainedEffectJournal,
}

/// Reservation refusal retains a creator that was built but never started.
#[must_use = "retain the unstarted creator and reconcile the journal"]
pub struct ReservationRefusal {
    /// Reason for refusal.
    pub reason: ReservationError,
    /// The selected identity and unstarted creator, if planning reached it.
    pub candidate: Option<(Identity, Worker)>,
}

/// Plan and pinned journal bound to one immutable storage configuration.
#[must_use = "retain the plan and its journal for recovery"]
pub struct ReservedPlan {
    plan: Plan,
    journal: PinRetainedEffectJournal,
    scope: ContentDigest,
    expected: Option<u64>,
    pending: Option<Identity>,
    fenced: bool,
}

/// What the reservation journal says about one candidate generation.
/// None of these states proves that its rollover switch became active.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InventoryDisposition {
    /// A reservation has no subsequent observation or reconciliation record.
    Pending,
    /// The exact creator was locally observed as installed.
    CreatorObserved,
    /// The caller recorded this evidence reference; its contents are unverified.
    Reconciled(ContentDigest),
}

/// One generation reconstructed from the exact retained reservation history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryEntry {
    /// Deterministically reconstructed store and pin locations.
    pub identity: Identity,
    /// Recorded disposition, not an active-switch classification.
    pub disposition: InventoryDisposition,
}

/// Continuation tied to the exact retained journal head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryCursor {
    snapshot: EffectJournalPin,
    after_generation: u64,
}

/// Bounded candidate page. A continuation is invalid after the head changes.
pub struct InventoryPage {
    /// Head checked against both journal and its supplied retainer.
    pub snapshot: EffectJournalPin,
    /// Candidates in increasing reservation order.
    pub entries: Vec<InventoryEntry>,
    /// Opaque continuation, present only when another candidate exists.
    pub next: Option<InventoryCursor>,
}

/// Complete bounded reservation inventory with all candidate switches opened.
/// Its caller must retain every owner and exclude concurrent writers.
#[must_use = "retain or explicitly reconcile all opened switch custody"]
pub struct OpenedSwitches {
    snapshot: EffectJournalPin,
    entries: Vec<InventoryEntry>,
    switches: Vec<PinRetainedEffectJournal>,
}

/// Failure to open or compare the complete candidate inventory.
#[derive(Debug)]
pub enum OpenSwitchesError {
    /// Reservation inventory verification failed.
    Inventory(InventoryError),
    /// The candidate limit was insufficient or allocation failed.
    Incomplete,
    /// Replay authority was withdrawn.
    Cancelled,
    /// The explicit work budget did not admit the storage-read ceilings.
    Work(GeometryError),
    /// A candidate store or pin custodian could not be opened or bound.
    Storage {
        /// Position in the verified inventory.
        index: usize,
        /// Storage refusal for that candidate.
        error: EffectPersistenceError,
    },
    /// The candidate retainer has no committed switch pin.
    MissingPin {
        /// Position in the verified inventory.
        index: usize,
    },
    /// The reservation inventory changed during opening or selection.
    Stale,
    /// The candidate switches could not be selected unambiguously.
    Selection(crate::unifi_direct::archive::journal::rollover::SwitchSelectionError),
}

/// A refusal retains every opened owner and any partially bound owner.
#[must_use = "retain or reconcile the opened and partially opened custody"]
pub struct OpenSwitchesRefusal {
    /// Classified reason for refusal.
    pub reason: OpenSwitchesError,
    /// Successfully opened candidate switches in inventory order.
    pub opened: Vec<PinRetainedEffectJournal>,
    /// Candidate journal opened before a binding refusal, if any.
    pub journal: Option<Box<dyn EffectJournalStore>>,
    /// Candidate retainer opened before a refusal, if any.
    pub retainer: Option<Box<dyn EffectPinRetainer>>,
}

impl OpenedSwitches {
    /// Identify the reservation entries represented by the owned switches.
    pub fn entries(&self) -> &[InventoryEntry] {
        &self.entries
    }

    /// Select against the same still-current complete reservation inventory.
    /// A match remains a candidate until its histories are recovered and
    /// replayed. All opened switch owners remain held on every result.
    pub fn select(
        &mut self,
        plan: &mut ReservedPlan,
        predecessor: crate::unifi_direct::archive::journal::rollover::SwitchPredecessor,
        max_records: usize,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<Option<crate::unifi_direct::archive::journal::rollover::SelectedSwitch>, OpenSwitchesError> {
        let limit = self.entries.len().max(1);
        let before = plan.inventory_page(None, limit, max_records, work, cx).map_err(OpenSwitchesError::Inventory)?;
        if before.snapshot != self.snapshot || before.entries != self.entries || before.next.is_some() {
            return Err(OpenSwitchesError::Stale);
        }
        let selected = crate::unifi_direct::archive::journal::rollover::select_successor_switch(
            predecessor, &mut self.switches, work, cx,
        ).map_err(OpenSwitchesError::Selection)?;
        let after = plan.inventory_page(None, limit, max_records, work, cx).map_err(OpenSwitchesError::Inventory)?;
        if after.snapshot != self.snapshot || after.entries != self.entries || after.next.is_some() {
            return Err(OpenSwitchesError::Stale);
        }
        Ok(selected)
    }

    /// Return the exact inventory snapshot and all switch owners in order.
    pub fn into_parts(self) -> (EffectJournalPin, Vec<InventoryEntry>, Vec<PinRetainedEffectJournal>) {
        (self.snapshot, self.entries, self.switches)
    }
}

/// Read-only inventory refusal; no reservation or switch is started.
#[derive(Debug)]
pub enum InventoryError {
    /// Page or scan bounds were invalid or too small for the full history.
    Limit,
    /// The continuation belongs to a different retained head.
    Stale,
    /// The reservation owner already requires cold reconciliation.
    Fenced,
    /// Replay authority or cancellation refused inspection.
    Cancelled,
    /// Bounded work was refused.
    Work(GeometryError),
    /// The reservation history or reconstructed identity was inconsistent.
    Invalid,
    /// Journal or pin-retainer verification failed; the owner is fenced.
    Storage(EffectPersistenceError),
}

/// Refusal to discover the next generation preserves the plan and journal.
#[must_use = "retain or reconcile the returned plan and journal"]
pub struct DiscoverRefusal {
    /// Why the retained history could not determine a safe next generation.
    pub reason: DiscoverError,
    /// Original plan, or the adjusted plan if final binding was attempted.
    pub plan: Plan,
    /// Original retained journal; storage errors may require a cold reopen.
    pub journal: PinRetainedEffectJournal,
}

/// Failure while deriving the next generation from retained history.
#[derive(Debug)]
pub enum DiscoverError {
    /// Caller limits or a generation range were invalid or exhausted.
    Limit,
    /// Replay authority or cancellation refused inspection.
    Cancelled,
    /// The explicit work allowance was exhausted or cancelled.
    Work(GeometryError),
    /// The retained header or latest record was invalid for this plan.
    Invalid,
    /// Journal or independent pin verification failed.
    Storage(EffectPersistenceError),
    /// Complete retained-history binding refused the discovered plan.
    Bind(ReservationError),
}

/// A local observation from the exact drained creator and installed custody.
/// This records neither independent storage trust nor camera-effect settlement.
/// Only the managed owner can construct one after matching its reserved identity.
pub struct CreatorObservation {
    identity: Identity,
}

impl CreatorObservation {
    pub(crate) fn from_installed(
        identity: &Identity,
        custody: &crate::unifi_direct::recording_provision::SupplyCustody,
        completion: &crate::unifi_direct::av_rollover_supplies::Completion,
    ) -> Option<Self> {
        let pin = custody.switch_custody.as_ref()?;
        if completion.runtime.is_err()
            || completion.outcome != crate::unifi_direct::av_rollover_supplies::Outcome::Ready
            || custody.root != identity.journal_root
            || pin.root != identity.pin_root
            || pin.scope != identity.pin_scope
            || custody.root.parent() != Some(custody.replay.root_dir())
            || pin.root.parent() != Some(pin.replay.root_dir())
        {
            return None;
        }
        Some(Self {
            identity: identity.clone(),
        })
    }

    pub(crate) fn identity(&self) -> &Identity {
        &self.identity
    }
}

fn checkpoint(cx: &ReplayCx) -> Result<(), ReservationError> {
    cx.checkpoint("unifi-generation-reservation")
        .map_err(|_| ReservationError::Cancelled)
}

fn scope(plan: &Plan) -> Result<ContentDigest, ReservationError> {
    let c = &plan.config;
    let mut out = CanonicalEncoder::new();
    out.text(SCOPE_DOMAIN);
    out.text(&c.namespace);
    out.digest(c.scope_seed);
    out.text(
        c.journal_replay
            .root_dir()
            .to_str()
            .ok_or(ReservationError::Invalid)?,
    );
    out.text(
        c.pin_replay
            .root_dir()
            .to_str()
            .ok_or(ReservationError::Invalid)?,
    );
    for limits in [c.journal_limits, c.pin_limits] {
        out.u64(u64::try_from(limits.max_records).map_err(|_| ReservationError::Invalid)?);
        out.u64(u64::try_from(limits.max_record_bytes).map_err(|_| ReservationError::Invalid)?);
        out.u64(limits.max_total_bytes);
        out.u64(limits.max_read_bytes);
    }
    for n in [
        c.object_limits.max_objects,
        c.object_limits.max_object_bytes,
        c.object_limits.max_total_bytes,
    ] {
        out.u64(u64::try_from(n).map_err(|_| ReservationError::Invalid)?);
    }
    out.u64(c.work_limit);
    Ok(ContentDigest::sha256(
        &out.finish_checked()
            .map_err(|_| ReservationError::Invalid)?,
    ))
}

fn identity_digest(identity: &Identity) -> Result<ContentDigest, ReservationError> {
    let mut out = CanonicalEncoder::new();
    out.text(ID_DOMAIN);
    out.u64(identity.generation);
    out.text(
        identity
            .journal_root
            .to_str()
            .ok_or(ReservationError::Invalid)?,
    );
    out.text(
        identity
            .pin_root
            .to_str()
            .ok_or(ReservationError::Invalid)?,
    );
    out.digest(identity.pin_scope);
    Ok(ContentDigest::sha256(
        &out.finish_checked()
            .map_err(|_| ReservationError::Invalid)?,
    ))
}

fn encode(
    scope: ContentDigest,
    kind: u8,
    generation: u64,
    identity: ContentDigest,
) -> Result<Vec<u8>, ReservationError> {
    let mut out = CanonicalEncoder::new();
    out.text(DOMAIN);
    out.digest(scope);
    out.u8(kind);
    out.u64(generation);
    out.digest(identity);
    let bytes = out
        .finish_checked()
        .map_err(|_| ReservationError::Invalid)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(ReservationError::Invalid);
    }
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<(ContentDigest, u8, u64, ContentDigest), ReservationError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(ReservationError::Invalid);
    }
    let mut input = CanonicalDecoder::new(bytes);
    if input.text().map_err(|_| ReservationError::Invalid)? != DOMAIN {
        return Err(ReservationError::Invalid);
    }
    let scope = input.digest().map_err(|_| ReservationError::Invalid)?;
    let kind = input.u8().map_err(|_| ReservationError::Invalid)?;
    let generation = input.u64().map_err(|_| ReservationError::Invalid)?;
    let identity = input.digest().map_err(|_| ReservationError::Invalid)?;
    input
        .ensure_finished()
        .map_err(|_| ReservationError::Invalid)?;
    if encode(scope, kind, generation, identity)? != bytes {
        return Err(ReservationError::Invalid);
    }
    Ok((scope, kind, generation, identity))
}

impl ReservedPlan {
    pub(crate) fn fence(&mut self) {
        self.fenced = true;
    }

    pub(crate) fn uses_replays(&self, journal: &std::sync::Arc<ReplayCx>, pin: &std::sync::Arc<ReplayCx>) -> bool {
        std::sync::Arc::ptr_eq(&self.plan.config.journal_replay, journal)
            && std::sync::Arc::ptr_eq(&self.plan.config.pin_replay, pin)
    }

    /// Bind a fresh plan to empty, separately retained custody. A failed append
    /// returns both owners and may require cold reconciliation.
    pub fn create(
        plan: Plan,
        journal: PinRetainedEffectJournal,
        cx: &ReplayCx,
    ) -> Result<Self, BindRefusal> {
        Self::create_guarded(plan, journal, cx, &mut || Ok(()))
    }

    pub(crate) fn create_guarded(
        plan: Plan,
        mut journal: PinRetainedEffectJournal,
        cx: &ReplayCx,
        guard: &mut dyn FnMut() -> Result<(), ReservationError>,
    ) -> Result<Self, BindRefusal> {
        let result = (|| {
            guard()?;
            checkpoint(cx)?;
            let scope = scope(&plan)?;
            if plan.next != plan.config.first
                || plan.remaining != plan.config.count
                || journal.head().is_some()
                || !journal.records().is_empty()
            {
                return Err(ReservationError::Invalid);
            }
            let bytes = encode(scope, 0, plan.next, scope)?;
            journal
                .append(None, &bytes)
                .map_err(ReservationError::Storage)?;
            guard()?;
            checkpoint(cx)?;
            Ok(scope)
        })();
        match result {
            Ok(scope) => {
                let expected = Some(plan.next);
                Ok(Self {
                    plan,
                    journal,
                    scope,
                    expected,
                    pending: None,
                    fenced: false,
                })
            }
            Err(reason) => Err(BindRefusal {
                reason,
                plan,
                journal,
            }),
        }
    }

    /// Reopen against the exact independently retained current head. The caller
    /// supplies a fresh plan beginning at the first unreserved generation.
    /// Reopening restores no permission to start or repeat a previous creator.
    pub fn recover(
        plan: Plan,
        journal: PinRetainedEffectJournal,
        cx: &ReplayCx,
    ) -> Result<Self, BindRefusal> {
        Self::recover_guarded(plan, journal, cx, &mut || Ok(()))
    }

    /// Recover a plan without knowing the first unreserved generation.
    ///
    /// The supplied plan's first generation must match the retained header;
    /// its count is the caller's finite allowance for future reservations. The
    /// complete journal and retained head are verified before the discovered
    /// next generation is bound. A pending reservation remains fenced from
    /// reuse and still needs explicit reconciliation. This does not locate an
    /// active switch or prove storage independence. This synchronous method
    /// performs I/O and belongs on a drained blocking worker.
    pub fn recover_discovered(
        plan: Plan,
        journal: PinRetainedEffectJournal,
        cx: &ReplayCx,
        max_records: usize,
        work: &mut WorkBudget<'_>,
    ) -> Result<Self, DiscoverRefusal> {
        Self::recover_discovered_guarded(plan, journal, cx, max_records, work, &mut || Ok(()))
    }

    pub(crate) fn recover_discovered_guarded(
        mut plan: Plan,
        mut journal: PinRetainedEffectJournal,
        cx: &ReplayCx,
        max_records: usize,
        work: &mut WorkBudget<'_>,
        guard: &mut dyn FnMut() -> Result<(), ReservationError>,
    ) -> Result<Self, DiscoverRefusal> {
        let result = (|| -> Result<u64, DiscoverError> {
            if plan.next != plan.config.first || plan.remaining != plan.config.count {
                return Err(DiscoverError::Invalid);
            }
            if !(1..=65_536).contains(&max_records) || journal.records().len() > max_records {
                return Err(DiscoverError::Limit);
            }
            guard().map_err(DiscoverError::Bind)?;
            checkpoint(cx).map_err(|_| DiscoverError::Cancelled)?;
            for record in journal.records() {
                guard().map_err(DiscoverError::Bind)?;
                checkpoint(cx).map_err(|_| DiscoverError::Cancelled)?;
                if record.len() > MAX_RECORD_BYTES {
                    return Err(DiscoverError::Invalid);
                }
                let cost = u64::try_from(record.len()).map_err(|_| DiscoverError::Limit)?
                    .checked_mul(16).and_then(|n| n.checked_add(130)).ok_or(DiscoverError::Limit)?;
                work.charge(cost).map_err(DiscoverError::Work)?;
            }
            let retained = journal.verify_retained_head().map_err(DiscoverError::Storage)?;
            let expected_scope = scope(&plan).map_err(|_| DiscoverError::Invalid)?;
            let records = journal.records();
            let (header_scope, kind, first, marker) = decode(records.first().ok_or(DiscoverError::Invalid)?)
                .map_err(|_| DiscoverError::Invalid)?;
            if header_scope != expected_scope || kind != 0 || first == 0
                || marker != expected_scope || first != plan.config.first
            {
                return Err(DiscoverError::Invalid);
            }
            let next = if records.len() == 1 {
                first
            } else {
                let (record_scope, kind, generation, _) = decode(records.last().ok_or(DiscoverError::Invalid)?)
                    .map_err(|_| DiscoverError::Invalid)?;
                if record_scope != expected_scope || !(1..=3).contains(&kind) || generation < first {
                    return Err(DiscoverError::Invalid);
                }
                generation.checked_add(1).ok_or(DiscoverError::Limit)?
            };
            next.checked_add(plan.config.count - 1).ok_or(DiscoverError::Limit)?;
            guard().map_err(DiscoverError::Bind)?;
            checkpoint(cx).map_err(|_| DiscoverError::Cancelled)?;
            if journal.verify_retained_head().map_err(DiscoverError::Storage)? != retained {
                return Err(DiscoverError::Invalid);
            }
            Ok(next)
        })();
        let next = match result {
            Ok(next) => next,
            Err(reason) => return Err(DiscoverRefusal { reason, plan, journal }),
        };
        plan.next = next;
        plan.config.first = next;
        Self::recover_guarded(plan, journal, cx, guard).map_err(|refusal| DiscoverRefusal {
            reason: DiscoverError::Bind(refusal.reason),
            plan: refusal.plan,
            journal: refusal.journal,
        })
    }

    pub(crate) fn recover_guarded(
        plan: Plan,
        mut journal: PinRetainedEffectJournal,
        cx: &ReplayCx,
        guard: &mut dyn FnMut() -> Result<(), ReservationError>,
    ) -> Result<Self, BindRefusal> {
        let result = (|| {
            guard()?;
            checkpoint(cx)?;
            journal
                .verify_retained_head()
                .map_err(ReservationError::Storage)?;
            let scope = scope(&plan)?;
            if plan.next != plan.config.first || plan.remaining != plan.config.count {
                return Err(ReservationError::Invalid);
            }
            let mut records = journal.records().iter();
            let (header_scope, kind, first, marker) =
                decode(records.next().ok_or(ReservationError::Invalid)?)?;
            if header_scope != scope || kind != 0 || first == 0 || marker != scope {
                return Err(ReservationError::Invalid);
            }
            let mut expected = Some(first);
            let mut pending: Option<Identity> = None;
            for record in records {
                guard()?;
                checkpoint(cx)?;
                let (record_scope, kind, generation, digest) = decode(record)?;
                if record_scope != scope {
                    return Err(ReservationError::Invalid);
                }
                match kind {
                    1 if pending.is_none() && Some(generation) == expected => {
                        let identity = plan
                            .identity_for(generation)
                            .map_err(ReservationError::Plan)?;
                        if identity_digest(&identity)? != digest {
                            return Err(ReservationError::Invalid);
                        }
                        pending = Some(identity);
                        expected = generation.checked_add(1);
                    }
                    2 if pending
                        .as_ref()
                        .is_some_and(|identity| identity.generation == generation)
                        && valid_evidence(digest) =>
                    {
                        pending = None;
                    }
                    3 if pending.as_ref().is_some_and(|identity| {
                        identity.generation == generation
                            && identity_digest(identity).is_ok_and(|expected| expected == digest)
                    }) =>
                    {
                        pending = None;
                    }
                    _ => return Err(ReservationError::Invalid),
                }
            }
            if expected != Some(plan.next) {
                return Err(ReservationError::Invalid);
            }
            guard()?;
            checkpoint(cx)?;
            Ok((scope, expected, pending))
        })();
        match result {
            Ok((scope, expected, pending)) => Ok(Self {
                plan,
                journal,
                scope,
                expected,
                pending,
                fenced: false,
            }),
            Err(reason) => Err(BindRefusal {
                reason,
                plan,
                journal,
            }),
        }
    }

    /// Durably reserve the next identity before returning its unstarted worker.
    /// On any refusal the owner fences; the caller must retain a returned
    /// candidate and reconcile rather than retrying or starting it.
    pub fn reserve_next(
        &mut self,
        cx: &ReplayCx,
    ) -> Result<Option<(Identity, Worker)>, ReservationRefusal> {
        self.reserve_next_guarded(cx, &mut || Ok(()))
    }

    pub(crate) fn reserve_next_guarded(
        &mut self,
        cx: &ReplayCx,
        guard: &mut dyn FnMut() -> Result<(), ReservationError>,
    ) -> Result<Option<(Identity, Worker)>, ReservationRefusal> {
        if self.fenced {
            return Err(ReservationRefusal {
                reason: ReservationError::Fenced,
                candidate: None,
            });
        }
        if self.pending.is_some() {
            return Err(ReservationRefusal {
                reason: ReservationError::ReconciliationRequired,
                candidate: None,
            });
        }
        if let Err(reason) = guard().and_then(|()| checkpoint(cx)) {
            self.fenced = true;
            return Err(ReservationRefusal {
                reason,
                candidate: None,
            });
        }
        let candidate = match self.plan.next_worker() {
            Ok(Some(candidate)) => candidate,
            Ok(None) => return Ok(None),
            Err(error) => {
                self.fenced = true;
                return Err(ReservationRefusal {
                    reason: ReservationError::Plan(error),
                    candidate: None,
                });
            }
        };
        let result = (|| {
            if Some(candidate.0.generation) != self.expected {
                return Err(ReservationError::Invalid);
            }
            let bytes = encode(
                self.scope,
                1,
                candidate.0.generation,
                identity_digest(&candidate.0)?,
            )?;
            guard()?;
            checkpoint(cx)?;
            self.journal
                .append(self.journal.head(), &bytes)
                .map_err(ReservationError::Storage)?;
            guard()?;
            checkpoint(cx)?;
            Ok(())
        })();
        if let Err(reason) = result {
            self.fenced = true;
            return Err(ReservationRefusal {
                reason,
                candidate: Some(candidate),
            });
        }
        self.expected = candidate.0.generation.checked_add(1);
        self.pending = Some(candidate.0.clone());
        Ok(Some(candidate))
    }

    /// The reservation requiring caller reconciliation, if any. Its presence
    /// does not establish whether storage creation was attempted or succeeded.
    pub fn pending(&self) -> Option<&Identity> {
        self.pending.as_ref()
    }

    /// Inspect a bounded page of candidate locations from the retained journal.
    ///
    /// This synchronous read performs retainer I/O and belongs on a drained
    /// blocking worker. It verifies the complete reservation history for each
    /// page; `max_records` and `work` bound that scan. A candidate is not proof
    /// of an active switch, and the caller must verify the switch and its pins.
    pub fn inventory_page(
        &mut self,
        cursor: Option<&InventoryCursor>,
        limit: usize,
        max_records: usize,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<InventoryPage, InventoryError> {
        if self.fenced {
            return Err(InventoryError::Fenced);
        }
        if !(1..=128).contains(&limit) || !(1..=65_536).contains(&max_records)
            || self.journal.records().len() > max_records
        {
            return Err(InventoryError::Limit);
        }
        let snapshot = self.journal.head().ok_or(InventoryError::Invalid)?;
        if cursor.is_some_and(|value| value.snapshot != snapshot) {
            return Err(InventoryError::Stale);
        }
        checkpoint(cx).map_err(|_| InventoryError::Cancelled)?;
        // Reserve bounded work before either complete retainer verification.
        for record in self.journal.records() {
            checkpoint(cx).map_err(|_| InventoryError::Cancelled)?;
            if record.len() > MAX_RECORD_BYTES {
                return Err(InventoryError::Invalid);
            }
            let cost = u64::try_from(record.len()).map_err(|_| InventoryError::Limit)?
                .checked_mul(8).and_then(|n| n.checked_add(65)).ok_or(InventoryError::Limit)?;
            work.charge(cost).map_err(InventoryError::Work)?;
        }
        let retained = match self.journal.verify_retained_head() {
            Ok(head) => head,
            Err(error) => {
                self.fenced = true;
                return Err(InventoryError::Storage(error));
            }
        };
        if retained != snapshot {
            self.fenced = true;
            return Err(InventoryError::Invalid);
        }
        let mut records = self.journal.records().iter();
        let (header_scope, kind, first, marker) = decode(records.next().ok_or(InventoryError::Invalid)?)
            .map_err(|_| InventoryError::Invalid)?;
        if header_scope != self.scope || kind != 0 || first == 0 || marker != self.scope {
            return Err(InventoryError::Invalid);
        }
        let mut entries = Vec::new();
        entries.try_reserve_exact(limit).map_err(|_| InventoryError::Limit)?;
        let mut has_more = false;
        let after = cursor.map(|value| value.after_generation);
        let mut expected = Some(first);
        let mut pending: Option<Identity> = None;
        let mut emit = |identity: Identity, disposition: InventoryDisposition| {
            if after.is_none_or(|generation| identity.generation > generation) {
                if entries.len() < limit {
                    entries.push(InventoryEntry { identity, disposition });
                } else {
                    has_more = true;
                }
            }
        };
        for record in records {
            checkpoint(cx).map_err(|_| InventoryError::Cancelled)?;
            let (scope, kind, generation, digest) = decode(record).map_err(|_| InventoryError::Invalid)?;
            if scope != self.scope {
                return Err(InventoryError::Invalid);
            }
            match kind {
                1 if pending.is_none() && Some(generation) == expected => {
                    let identity = self.plan.identity_for(generation).map_err(|_| InventoryError::Invalid)?;
                    if identity_digest(&identity).map_err(|_| InventoryError::Invalid)? != digest {
                        return Err(InventoryError::Invalid);
                    }
                    expected = generation.checked_add(1);
                    pending = Some(identity);
                }
                2 if pending.as_ref().is_some_and(|value| value.generation == generation)
                    && valid_evidence(digest) => {
                    emit(pending.take().ok_or(InventoryError::Invalid)?, InventoryDisposition::Reconciled(digest));
                }
                3 if pending.as_ref().is_some_and(|value| value.generation == generation
                    && identity_digest(value).is_ok_and(|expected| expected == digest)) => {
                    emit(pending.take().ok_or(InventoryError::Invalid)?, InventoryDisposition::CreatorObserved);
                }
                _ => return Err(InventoryError::Invalid),
            }
        }
        if expected != self.expected || pending != self.pending {
            return Err(InventoryError::Invalid);
        }
        if let Some(identity) = pending {
            emit(identity, InventoryDisposition::Pending);
        }
        checkpoint(cx).map_err(|_| InventoryError::Cancelled)?;
        let head = match self.journal.verify_retained_head() {
            Ok(head) => head,
            Err(error) => {
                self.fenced = true;
                return Err(InventoryError::Storage(error));
            }
        };
        if head != snapshot {
            self.fenced = true;
            return Err(InventoryError::Invalid);
        }
        let next = if has_more {
            Some(InventoryCursor { snapshot, after_generation: entries.last().ok_or(InventoryError::Invalid)?.identity.generation })
        } else {
            None
        };
        Ok(InventoryPage { snapshot, entries, next })
    }

    /// Open every switch in one complete, bounded reservation inventory.
    ///
    /// The caller explicitly trusts each candidate's configured pin-storage
    /// root as a recovery authority, and must exclude concurrent writers.
    /// Missing or empty candidates are refused, including pending reservations;
    /// they are never silently classified as absent. The storage read ceilings
    /// are charged to `work` before each open. This blocking I/O must run on a
    /// drained worker; trust in physical independence is not established here.
    pub fn open_switches_trusting_custody(
        &mut self,
        max_candidates: usize,
        max_records: usize,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<OpenedSwitches, OpenSwitchesRefusal> {
        let mut opened = Vec::new();
        macro_rules! refuse {
            ($reason:expr, $journal:expr, $retainer:expr) => {
                return Err(OpenSwitchesRefusal { reason: $reason, opened, journal: $journal, retainer: $retainer })
            };
        }
        if !(1..=128).contains(&max_candidates) {
            refuse!(OpenSwitchesError::Incomplete, None, None);
        }
        let page = match self.inventory_page(None, max_candidates, max_records, work, cx) {
            Ok(page) => page,
            Err(error) => refuse!(OpenSwitchesError::Inventory(error), None, None),
        };
        if page.next.is_some() || opened.try_reserve_exact(page.entries.len()).is_err() {
            refuse!(OpenSwitchesError::Incomplete, None, None);
        }
        let config = &self.plan.config;
        for (index, entry) in page.entries.iter().enumerate() {
            if checkpoint(cx).is_err() || checkpoint(&config.journal_replay).is_err()
                || checkpoint(&config.pin_replay).is_err()
            {
                refuse!(OpenSwitchesError::Cancelled, None, None);
            }
            let allowance = match config.journal_limits.max_read_bytes.checked_add(config.pin_limits.max_read_bytes) {
                Some(value) => value,
                None => refuse!(OpenSwitchesError::Incomplete, None, None),
            };
            if let Err(error) = work.charge(allowance) {
                refuse!(OpenSwitchesError::Work(error), None, None);
            }
            let mut retainer: Box<dyn EffectPinRetainer> = match FileTrustedRootPinRetainer::open_trusting_storage(
                &entry.identity.pin_root, config.pin_limits, config.pin_io.clone(), entry.identity.pin_scope,
            ) {
                Ok(value) => Box::new(value),
                Err(error) => refuse!(OpenSwitchesError::Storage { index, error }, None, None),
            };
            if checkpoint(cx).is_err() || checkpoint(&config.pin_replay).is_err() {
                refuse!(OpenSwitchesError::Cancelled, None, Some(retainer));
            }
            let pin = match retainer.retained_pin() {
                Ok(Some(pin)) => pin,
                Ok(None) => refuse!(OpenSwitchesError::MissingPin { index }, None, Some(retainer)),
                Err(error) => refuse!(OpenSwitchesError::Storage { index, error }, None, Some(retainer)),
            };
            let journal: Box<dyn EffectJournalStore> = match FileEffectJournal::open(
                entry.identity.journal_root.join("switch"), config.journal_limits, config.journal_io.clone(), pin,
            ) {
                Ok(value) => Box::new(value),
                Err(error) => refuse!(OpenSwitchesError::Storage { index, error }, None, Some(retainer)),
            };
            if checkpoint(cx).is_err() || checkpoint(&config.journal_replay).is_err() {
                refuse!(OpenSwitchesError::Cancelled, Some(journal), Some(retainer));
            }
            match PinRetainedEffectJournal::try_for_reconciliation(journal, retainer) {
                Ok(value) => opened.push(value),
                Err(refusal) => refuse!(OpenSwitchesError::Storage { index, error: refusal.error }, Some(refusal.journal), Some(refusal.retainer)),
            }
        }
        let refreshed = match self.inventory_page(None, max_candidates, max_records, work, cx) {
            Ok(value) => value,
            Err(error) => refuse!(OpenSwitchesError::Inventory(error), None, None),
        };
        if refreshed.snapshot != page.snapshot || refreshed.entries != page.entries || refreshed.next.is_some() {
            refuse!(OpenSwitchesError::Stale, None, None);
        }
        Ok(OpenedSwitches { snapshot: page.snapshot, entries: page.entries, switches: opened })
    }

    /// Unreserved generations in the caller's current finite plan.
    pub fn remaining(&self) -> u64 {
        self.plan.remaining()
    }

    pub(crate) fn record_creator_observation_guarded(
        &mut self,
        identity: &Identity,
        cx: &ReplayCx,
        guard: &mut dyn FnMut() -> Result<(), ReservationError>,
    ) -> Result<EffectJournalPin, ReservationError> {
        if self.fenced {
            return Err(ReservationError::Fenced);
        }
        if self.pending.as_ref() != Some(identity) {
            return Err(ReservationError::Invalid);
        }
        let result = (|| {
            guard()?;
            checkpoint(cx)?;
            let bytes = encode(
                self.scope,
                3,
                identity.generation,
                identity_digest(identity)?,
            )?;
            let pin = self
                .journal
                .append(self.journal.head(), &bytes)
                .map_err(ReservationError::Storage)?;
            guard()?;
            checkpoint(cx)?;
            Ok(pin)
        })();
        match result {
            Ok(pin) => {
                self.pending = None;
                Ok(pin)
            }
            Err(error) => {
                self.fenced = true;
                Err(error)
            }
        }
    }

    /// Record the caller's reconciliation evidence for the exact reservation.
    /// The digest is a caller-supplied evidence reference, not verification of
    /// its contents, storage independence, or a camera effect. A failed write
    /// fences the owner and must be cold-reconciled before further reservations.
    pub fn record_reconciliation(
        &mut self,
        identity: &Identity,
        evidence: ContentDigest,
        cx: &ReplayCx,
    ) -> Result<EffectJournalPin, ReservationError> {
        self.record_reconciliation_guarded(identity, evidence, cx, &mut || Ok(()))
    }

    pub(crate) fn record_reconciliation_guarded(
        &mut self,
        identity: &Identity,
        evidence: ContentDigest,
        cx: &ReplayCx,
        guard: &mut dyn FnMut() -> Result<(), ReservationError>,
    ) -> Result<EffectJournalPin, ReservationError> {
        if self.fenced {
            return Err(ReservationError::Fenced);
        }
        if self.pending.as_ref() != Some(identity) || !valid_evidence(evidence) {
            return Err(ReservationError::Invalid);
        }
        let result = (|| {
            guard()?;
            checkpoint(cx)?;
            let bytes = encode(self.scope, 2, identity.generation, evidence)?;
            let pin = self
                .journal
                .append(self.journal.head(), &bytes)
                .map_err(ReservationError::Storage)?;
            guard()?;
            checkpoint(cx)?;
            Ok(pin)
        })();
        match result {
            Ok(pin) => {
                self.pending = None;
                Ok(pin)
            }
            Err(error) => {
                self.fenced = true;
                Err(error)
            }
        }
    }

    /// Explicitly authorize another in-memory batch; no storage I/O is done.
    pub fn extend(&mut self, count: u64) -> Result<(), ReservationError> {
        if self.fenced {
            return Err(ReservationError::Fenced);
        }
        if self.pending.is_some() {
            return Err(ReservationError::ReconciliationRequired);
        }
        self.plan.extend(count).map_err(ReservationError::Plan)
    }

    /// Current acknowledged journal head, not an authentication or effect receipt.
    pub fn head(&self) -> Option<EffectJournalPin> {
        self.journal.head()
    }

    /// Recover both owners, including after an indeterminate write.
    pub fn into_parts(self) -> (Plan, PinRetainedEffectJournal) {
        (self.plan, self.journal)
    }
}

fn valid_evidence(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256
        && !digest.is_laboratory()
        && digest.bytes() != [0; 32]
}
