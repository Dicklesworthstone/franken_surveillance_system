#![forbid(unsafe_code)]
//! Staging and separately retained activation of a bounded journal successor.
//!
//! This is not yet a restart supervisor: callers must retain both original
//! histories and independently discover the switch and its custody on recovery.
//! No deletion, physical independence, or exclusive writer across processes
//! is established by this module.

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest};
use fss_geometry::WorkBudget;
use fss_publication::{RootLedgerOutcome, RootLedgerReceipt};
use fss_runtime::effect_journal::{
    EffectJournalPin, EffectJournalStore, EffectPersistenceError, PinRetainedEffectJournal,
};

use super::{Error, UnknownTimeAnchorKeeper, UnknownTimeJournal, checkpoint, valid_digest};
use crate::{
    ReferenceDeployment, ReplayCx,
    unifi_direct::{archive, archive::UnknownTimePin, source_evidence},
};

const DOMAIN: &str = "fss.unifi-direct.unknown-time-rollover.v1";
const MAX_SWITCH_BYTES: usize = 512;

/// Exact predecessor owners. The caller remains responsible for their storage.
#[must_use = "retain or explicitly reconcile both predecessor histories"]
pub struct Previous {
    /// Publication history.
    pub journal: UnknownTimeJournal,
    /// Separate publication-anchor history.
    pub keeper: UnknownTimeAnchorKeeper,
}

/// Payload-free transition identity; no authority or physical identity is implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Binding {
    /// Shared immutable publication scope.
    pub scope: ContentDigest,
    /// Last confirmed predecessor root.
    pub confirmed: UnknownTimePin,
    /// Final predecessor publication head.
    pub old_journal: EffectJournalPin,
    /// Final predecessor keeper head.
    pub old_keeper: EffectJournalPin,
    /// Seeded successor publication head.
    pub new_journal: EffectJournalPin,
    /// Seeded successor keeper head.
    pub new_keeper: EffectJournalPin,
}

/// Independently retained current heads of the successor histories.
/// A retained prefix alone is insufficient to activate a successor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuccessorHeads {
    /// Exact independently retained publication-journal head.
    pub journal: EffectJournalPin,
    /// Exact independently retained keeper head.
    pub keeper: EffectJournalPin,
}

/// Failure while staging; the original owners are returned unchanged.
#[must_use = "inspect any partially created successor stores before reuse"]
pub struct BeginRefusal {
    /// Failure classification.
    pub reason: Error,
    /// Original predecessor owners.
    pub previous: Previous,
}

/// Successor held out of service until a separate switch is retained.
#[must_use = "commit the switch or explicitly retire all candidate storage"]
pub struct Staged {
    previous: Previous,
    next_journal: UnknownTimeJournal,
    next_keeper: UnknownTimeAnchorKeeper,
    binding: Binding,
}

/// Refusal before a switch append, preserving all owners.
#[must_use = "retain or explicitly retire the staged candidate"]
pub struct CommitRefusal {
    /// Failure classification.
    pub reason: Error,
    /// The candidate remains unactivated.
    pub staged: Staged,
    /// The switch store has not been appended by this operation.
    pub switch: PinRetainedEffectJournal,
}

/// A switch append may have happened; neither history may be used blindly.
#[must_use = "cold-reconcile the exact switch and both histories"]
pub struct Indeterminate {
    staged: Staged,
    switch: PinRetainedEffectJournal,
}

/// Commit either refused before append or requires cold reconciliation.
#[must_use = "inspect the refusal or reconcile the uncertain switch"]
pub enum CommitError {
    /// The operation did not attempt the switch append.
    Before(CommitRefusal),
    /// A switch or its independently retained pin may have been written.
    Indeterminate(Indeterminate),
}

/// Active successor plus retained predecessor and switch owners.
#[must_use = "retain the predecessor and switch for restart recovery"]
pub struct Active {
    previous: Previous,
    next_journal: UnknownTimeJournal,
    next_keeper: UnknownTimeAnchorKeeper,
    switch: PinRetainedEffectJournal,
    binding: Binding,
    switch_head: EffectJournalPin,
}

/// A failed cold recovery retains all supplied owners for explicit inspection.
/// It does not authorize using either history or retrying a switch write.
#[must_use = "inspect the exact retained histories and switch"]
pub struct RecoveryRefusal {
    /// Payload-free failure classification.
    pub reason: Error,
    previous: Previous,
    successor: Previous,
    switch: PinRetainedEffectJournal,
}

/// Failure to revalidate and replay a rolled standalone source root.
#[derive(Debug)]
pub enum SourceReplayError {
    /// The retained switch, authority, or journal state failed verification.
    History(Error),
    /// The source root could not be read and verified under current authority.
    Readback(archive::Error),
    /// The retained camera claim did not match the caller's expected claim.
    ClaimMismatch,
    /// Exact-root publication failed or may require reconciliation.
    Publication(archive::UnknownTimePublishError),
    /// The root was not reported as already ledgered; retain the actual receipt.
    UnexpectedReceipt(Box<RootLedgerReceipt>),
}

impl std::fmt::Display for SourceReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::History(_) => "rollover history requires reconciliation",
            Self::Readback(_) => "rollover source readback refused",
            Self::ClaimMismatch => "rollover source claim mismatch",
            Self::Publication(_) => "rollover source publication requires reconciliation",
            Self::UnexpectedReceipt(_) => "rollover source was not already ledgered",
        })
    }
}
impl std::error::Error for SourceReplayError {}

struct SourceReplayGate<'a> {
    read: &'a dyn archive::ReadAuthority,
    retain: &'a dyn archive::RetainAuthority,
}
impl archive::RetainAuthority for SourceReplayGate<'_> {
    fn permits(&self, retention: ContentDigest, root: ContentDigest) -> bool {
        self.read.permits(retention, root) && self.retain.permits(retention, root)
    }
}

impl RecoveryRefusal {
    /// Current observed heads; these do not establish which history is active.
    pub fn observed_heads(&self) -> (EffectJournalPin, EffectJournalPin, Option<EffectJournalPin>) {
        (
            self.previous.journal.anchor(),
            self.successor.journal.anchor(),
            self.switch.head(),
        )
    }
}

fn encode(binding: Binding) -> Result<Vec<u8>, Error> {
    if !valid_digest(binding.scope)
        || !valid_digest(binding.confirmed.root)
        || !valid_digest(binding.confirmed.retention)
        || binding.old_journal.sequence <= 3
        || binding.new_journal.sequence != 3
        || binding.new_keeper.sequence != 1
        || binding.old_journal == binding.new_journal
    {
        return Err(Error::Invalid);
    }
    let mut out = CanonicalEncoder::new();
    out.text(DOMAIN);
    out.digest(binding.scope);
    out.digest(binding.confirmed.root);
    out.digest(binding.confirmed.retention);
    for pin in [
        binding.old_journal,
        binding.old_keeper,
        binding.new_journal,
        binding.new_keeper,
    ] {
        if pin.sequence == 0 || !valid_digest(pin.root) {
            return Err(Error::Invalid);
        }
        out.u64(pin.sequence);
        out.digest(pin.root);
    }
    let bytes = out.finish_checked().map_err(|_| Error::Invalid)?;
    if bytes.len() > MAX_SWITCH_BYTES {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<Binding, Error> {
    if bytes.len() > MAX_SWITCH_BYTES {
        return Err(Error::Invalid);
    }
    let mut input = CanonicalDecoder::new(bytes);
    if input.text().map_err(|_| Error::Invalid)? != DOMAIN {
        return Err(Error::Invalid);
    }
    let scope = input.digest().map_err(|_| Error::Invalid)?;
    let confirmed = UnknownTimePin {
        root: input.digest().map_err(|_| Error::Invalid)?,
        retention: input.digest().map_err(|_| Error::Invalid)?,
    };
    let mut pin = || -> Result<EffectJournalPin, Error> {
        Ok(EffectJournalPin {
            sequence: input.u64().map_err(|_| Error::Invalid)?,
            root: input.digest().map_err(|_| Error::Invalid)?,
        })
    };
    let binding = Binding {
        scope,
        confirmed,
        old_journal: pin()?,
        old_keeper: pin()?,
        new_journal: pin()?,
        new_keeper: pin()?,
    };
    input.ensure_finished().map_err(|_| Error::Invalid)?;
    if encode(binding)? != bytes {
        return Err(Error::Invalid);
    }
    Ok(binding)
}

/// Verify an already retained switch against cold-reopened histories.
///
/// The caller must find the switch independently, open it through
/// `PinRetainedEffectJournal::for_reconciliation`, and open both complete
/// history pairs at independently retained minima. `heads` must be the current
/// independently retained successor heads, not merely an earlier prefix.
/// This function does not
/// discover paths, prove physical storage independence, settle a pending
/// publication, or prove that no other process holds a writer. It never
/// appends. Each successor still requires exact-root archive replay before
/// another publication can be admitted.
pub fn recover(
    previous: Previous,
    successor: Previous,
    mut switch: PinRetainedEffectJournal,
    heads: SuccessorHeads,
    cx: &ReplayCx,
) -> Result<Active, RecoveryRefusal> {
    let checked = (|| {
        checkpoint(cx)?;
        let switch_head = switch.verify_retained_head().map_err(Error::Storage)?;
        if switch.records().len() != 1 || switch_head.sequence != 1 {
            return Err(Error::Invalid);
        }
        let binding = decode(&switch.records()[0])?;
        let old = &previous.journal;
        let old_keeper = &previous.keeper;
        let new = &successor.journal;
        let new_keeper = &successor.keeper;
        if old.inner.is_fenced()
            || old_keeper.is_fenced()
            || new.inner.is_fenced()
            || new_keeper.is_fenced()
            || old.scope() != binding.scope
            || new.scope() != binding.scope
            || old.anchor() != binding.old_journal
            || old_keeper.anchor() != binding.old_keeper
            || old_keeper.target() != binding.old_journal
            || old.pending().is_some()
            || old.confirmed() != Some(binding.confirmed)
            || old.replay_pin() != Some(binding.confirmed)
            || new.pending().is_some()
            || new.confirmed().is_none()
            || new.replay_pin() != new.confirmed()
            || new.anchor() != heads.journal
            || new_keeper.anchor() != heads.keeper
            || new_keeper.target() != new.anchor()
            || !new.inner.store.contains(binding.new_journal)
            || !new_keeper.inner.store.contains(binding.new_keeper)
        {
            return Err(Error::Invalid);
        }
        let records = new.inner.store.records();
        if records.len() < 3
            || records[0] != super::encode(super::UNKNOWN_TIME_DOMAIN, binding.scope, 0, None)?
            || records[1]
                != super::encode(
                    super::UNKNOWN_TIME_DOMAIN,
                    binding.scope,
                    1,
                    Some(binding.confirmed.access_pin()),
                )?
            || records[2]
                != super::encode(
                    super::UNKNOWN_TIME_DOMAIN,
                    binding.scope,
                    2,
                    Some(binding.confirmed.access_pin()),
                )?
            || new_keeper
                .inner
                .store
                .records()
                .first()
                .is_none_or(|record| {
                    super::decode_anchor(record, binding.scope).ok() != Some(binding.new_journal)
                })
        {
            return Err(Error::Invalid);
        }
        checkpoint(cx)?;
        Ok((binding, switch_head))
    })();
    match checked {
        Ok((binding, switch_head)) => Ok(Active {
            previous,
            next_journal: successor.journal,
            next_keeper: successor.keeper,
            switch,
            binding,
            switch_head,
        }),
        Err(reason) => Err(RecoveryRefusal {
            reason,
            previous,
            successor,
            switch,
        }),
    }
}

impl Staged {
    /// Seed a fresh successor from a settled and caught-up predecessor.
    ///
    /// Both new stores must be exclusive and empty. An error may leave a
    /// partially written successor on disk; it never modifies `previous`.
    /// The predecessor must contain more than the successor's three seed
    /// records so the two histories cannot have the same exact head.
    pub fn begin(
        previous: Previous,
        next_journal_store: Box<dyn EffectJournalStore>,
        next_keeper_store: Box<dyn EffectJournalStore>,
        cx: &ReplayCx,
    ) -> Result<Self, BeginRefusal> {
        let result = (|| {
            checkpoint(cx)?;
            let old = &previous.journal;
            let keeper = &previous.keeper;
            let confirmed = old.confirmed().ok_or(Error::Invalid)?;
            if old.inner.is_fenced()
                || keeper.is_fenced()
                || old.pending().is_some()
                || old.replay_pin().is_some()
                || keeper.target() != old.anchor()
                || old.anchor().sequence <= 3
            {
                return Err(Error::Invalid);
            }
            let scope = old.scope();
            let mut next_journal = UnknownTimeJournal::create(next_journal_store, scope, cx)?;
            next_journal.prepare(confirmed, cx)?;
            next_journal.confirm(confirmed, cx)?;
            // Reconciliation must verify the original root before another candidate.
            next_journal.inner.replay_pin = Some(confirmed.access_pin());
            let next_keeper =
                UnknownTimeAnchorKeeper::create(next_keeper_store, &next_journal, cx)?;
            let binding = Binding {
                scope,
                confirmed,
                old_journal: old.anchor(),
                old_keeper: keeper.anchor(),
                new_journal: next_journal.anchor(),
                new_keeper: next_keeper.anchor(),
            };
            encode(binding)?;
            Ok((next_journal, next_keeper, binding))
        })();
        match result {
            Ok((next_journal, next_keeper, binding)) => Ok(Self {
                previous,
                next_journal,
                next_keeper,
                binding,
            }),
            Err(reason) => Err(BeginRefusal { reason, previous }),
        }
    }

    /// Binding to retain with the caller's store locations and independent pins.
    pub fn binding(&self) -> Binding {
        self.binding
    }

    /// Append and independently retain one exact switch before exposing a successor.
    /// A failure during append or readback is indeterminate and cannot be retried.
    pub fn commit(
        self,
        mut switch: PinRetainedEffectJournal,
        cx: &ReplayCx,
    ) -> Result<Active, CommitError> {
        let bytes = match (|| {
            checkpoint(cx)?;
            if switch.head().is_some()
                || !switch.records().is_empty()
                || self.previous.journal.anchor() != self.binding.old_journal
                || self.previous.keeper.anchor() != self.binding.old_keeper
                || self.previous.keeper.target() != self.binding.old_journal
                || self.next_journal.anchor() != self.binding.new_journal
                || self.next_keeper.anchor() != self.binding.new_keeper
                || self.next_keeper.target() != self.binding.new_journal
                || self.next_journal.replay_pin() != Some(self.binding.confirmed)
            {
                return Err(Error::Invalid);
            }
            let bytes = encode(self.binding)?;
            switch
                .reserve_capacity(1, bytes.len())
                .map_err(Error::Storage)?;
            checkpoint(cx)?;
            Ok(bytes)
        })() {
            Ok(bytes) => bytes,
            Err(reason) => {
                return Err(CommitError::Before(CommitRefusal {
                    reason,
                    staged: self,
                    switch,
                }));
            }
        };
        let result = (|| {
            let head = switch.append(None, &bytes)?;
            if switch.verify_retained_head()? != head
                || switch.records().len() != 1
                || switch.records()[0] != bytes
            {
                return Err(EffectPersistenceError::PinMismatch);
            }
            checkpoint(cx).map_err(|_| {
                EffectPersistenceError::Storage("authority withdrawn after switch".into())
            })?;
            Ok(head)
        })();
        match result {
            Ok(switch_head) => Ok(Active {
                previous: self.previous,
                next_journal: self.next_journal,
                next_keeper: self.next_keeper,
                switch,
                binding: self.binding,
                switch_head,
            }),
            Err(_) => Err(CommitError::Indeterminate(Indeterminate {
                staged: self,
                switch,
            })),
        }
    }
}

impl Indeterminate {
    /// Exact candidate binding; this does not classify the attempted switch.
    pub fn binding(&self) -> Binding {
        self.staged.binding
    }
    /// Locally observed switch head; it may not have independent custody.
    pub fn observed_switch_head(&self) -> Option<EffectJournalPin> {
        self.switch.head()
    }
}

impl Active {
    /// Switch binding, not an independently retained recovery locator.
    pub fn binding(&self) -> Binding {
        self.binding
    }
    /// Switch head which the supplied retainer acknowledged.
    pub fn switch_head(&self) -> EffectJournalPin {
        self.switch_head
    }

    /// Verify and replay the exact ledgered standalone-source root after rollover.
    ///
    /// Both access policies and the retained switch are rechecked. Success
    /// requires an `AlreadyLedgered` receipt and clears only this successor's
    /// in-memory replay fence. The expected camera value is a caller-supplied
    /// claim, not device authentication. This neither starts a worker nor
    /// proves continuous coverage, physical time, or independent custody.
    pub fn replay_confirmed_source(
        &mut self,
        deployment: &mut ReferenceDeployment,
        expected_camera_claim: ContentDigest,
        read: &dyn archive::ReadAuthority,
        retain: &dyn archive::RetainAuthority,
        limits: archive::Limits,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<RootLedgerReceipt, SourceReplayError> {
        checkpoint(cx).map_err(SourceReplayError::History)?;
        let head = self
            .switch
            .verify_retained_head()
            .map_err(|e| SourceReplayError::History(Error::Storage(e)))?;
        let pin = self
            .next_journal
            .confirmed()
            .ok_or(SourceReplayError::History(Error::Invalid))?;
        if head != self.switch_head
            || self.switch.records().len() != 1
            || self.switch.records()[0]
                != encode(self.binding).map_err(SourceReplayError::History)?
            || self.next_journal.pending().is_some()
            || self.next_journal.replay_pin() != Some(pin)
            || self.next_keeper.target() != self.next_journal.anchor()
            || !valid_digest(expected_camera_claim)
        {
            return Err(SourceReplayError::History(Error::Invalid));
        }
        let source = archive::read_unknown_time_source(deployment, pin, read, limits, work, cx)
            .map_err(SourceReplayError::Readback)?;
        if source.camera_claim() != expected_camera_claim {
            return Err(SourceReplayError::ClaimMismatch);
        }
        let plan = source_evidence::Prepared::from_recovered(&source);
        let gate = SourceReplayGate { read, retain };
        let receipt = archive::publish_unknown_time_source_anchored(
            &plan,
            deployment,
            &gate,
            limits,
            work,
            cx,
            &mut self.next_journal,
            &mut self.next_keeper,
        )
        .map_err(SourceReplayError::Publication)?;
        if receipt.outcome != RootLedgerOutcome::AlreadyLedgered {
            self.next_journal.inner.replay_pin = Some(pin.access_pin());
            return Err(SourceReplayError::UnexpectedReceipt(Box::new(receipt)));
        }
        Ok(receipt)
    }
    /// The predecessor and switch remain owned while the successor is in use.
    /// The successor's exact confirmed root must still be replayed before a
    /// different candidate is accepted.
    pub fn successor(&mut self) -> (&mut UnknownTimeJournal, &mut UnknownTimeAnchorKeeper) {
        (&mut self.next_journal, &mut self.next_keeper)
    }
    /// Read-only observation of the retained predecessor heads.
    pub fn predecessor_heads(&self) -> (EffectJournalPin, EffectJournalPin) {
        (
            self.previous.journal.anchor(),
            self.previous.keeper.anchor(),
        )
    }
    /// Current locally observed switch head, without a fresh I/O verification.
    pub fn observed_switch_head(&self) -> Option<EffectJournalPin> {
        self.switch.head()
    }
}
