#![forbid(unsafe_code)]
//! Independently retained generation reservations. These synchronous calls
//! perform storage I/O and must run on a drained, region-owned blocking worker.
//! They do not prove physical custody independence or reconcile a created store.

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_runtime::effect_journal::{
    EffectJournalPin, EffectJournalStore, EffectPersistenceError, PinRetainedEffectJournal,
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
