#![forbid(unsafe_code)]
//! Staging and separately retained activation of a bounded journal successor.
//!
//! This is not yet a restart supervisor: callers must retain both original
//! histories and independently discover the switch and its custody on recovery.
//! No deletion, physical independence, or exclusive writer across processes
//! is established by this module.

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest};
use fss_geometry::{GeometryError, WorkBudget};
use fss_publication::{RootLedgerOutcome, RootLedgerReceipt};
use fss_runtime::effect_journal::{
    EffectJournalPin, EffectJournalStore, EffectPersistenceError, PinRetainedEffectJournal,
};
use std::rc::Rc;

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

/// A switch record checked against its supplied retained journal head.
/// The binding is a candidate transition, not proof of the active lineage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SwitchObservation {
    /// Canonical transition named by the retained switch.
    pub binding: Binding,
    /// Exact retained switch head checked before and after inspection.
    pub head: EffectJournalPin,
}

/// Failure to inspect one candidate switch without writing to it.
#[derive(Debug)]
pub enum SwitchInspectionError {
    /// Storage, encoding, or replay authority refused the inspection.
    History(Error),
    /// The caller's explicit work allowance was insufficient or cancelled.
    Work(GeometryError),
    /// The switch belongs to a different caller-supplied publication scope.
    ScopeMismatch,
}

/// Exact predecessor state used to match a candidate transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SwitchPredecessor {
    /// Expected publication scope.
    pub scope: ContentDigest,
    /// Confirmed predecessor root.
    pub confirmed: UnknownTimePin,
    /// Current predecessor publication head.
    pub journal: EffectJournalPin,
    /// Current predecessor keeper head.
    pub keeper: EffectJournalPin,
}

/// An index into the exact candidate slice supplied for this selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedSwitch {
    /// Position in the supplied slice, not a persistent identifier.
    pub index: usize,
    /// Checked retained switch and its claimed transition.
    pub observation: SwitchObservation,
}

/// Candidate selection refuses incomplete inspection and competing switches.
#[derive(Debug)]
pub enum SwitchSelectionError {
    /// More than 128 candidates were supplied.
    Limit,
    /// Predecessor identity or replay authority was invalid.
    History(Error),
    /// A candidate or replay authority could not be checked.
    Candidate {
        /// Candidate position in the supplied slice.
        index: usize,
        /// Inspection failure for that candidate.
        reason: SwitchInspectionError,
    },
    /// More than one supplied candidate claims the exact predecessor.
    Ambiguous,
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

/// Retained predecessors and switches while an archive worker owns the successor.
/// This is an in-memory lineage, not a compacted or independently stored chain.
#[must_use = "retain or explicitly reconcile this rollover custody"]
pub struct WorkerCustody {
    transitions: Vec<WorkerTransition>,
}

struct WorkerTransition {
    previous: Previous,
    switch: PinRetainedEffectJournal,
    binding: Binding,
    switch_head: EffectJournalPin,
}

/// A read-only view of a verified, settled in-memory journal lineage.
/// Retaining this view holds both the lineage and current journal borrowed.
pub struct History<'a> {
    custody: &'a WorkerCustody,
    current: &'a UnknownTimeJournal,
    identity: Rc<()>,
}

/// Position bound to the exact history view that produced it.
#[derive(Clone, Debug)]
pub struct HistoryCursor {
    identity: Rc<()>,
    generation: usize,
    after: u64,
}

/// One bounded page; entries are ordered from the oldest generation forward.
pub struct HistoryPage {
    /// Confirmed roots, with each rollover's repeated seed excluded.
    pub entries: Vec<HistoryEntry>,
    /// Resume position; a final continuation may produce an empty page.
    pub next: Option<HistoryCursor>,
}

/// One confirmation with its position in this particular lineage view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryEntry {
    /// Zero-based generation, oldest first; not a durable generation ID.
    pub generation: usize,
    /// One-based confirmation sequence within that journal generation.
    pub sequence: u64,
    /// Confirmed root and retention claim, not a media-read grant.
    pub pin: UnknownTimePin,
}

impl History<'_> {
    /// Count the verified journal generations in this view.
    pub fn generation_count(&self) -> usize {
        self.custody.transitions.len() + 1
    }

    fn journal(&self, generation: usize) -> Option<&UnknownTimeJournal> {
        if generation == self.custody.transitions.len() {
            Some(self.current)
        } else {
            self.custody
                .transitions
                .get(generation)
                .map(|transition| &transition.previous.journal)
        }
    }

    /// Read at most 128 roots. A cursor from another view is refused. The
    /// result identifies journaled roots, not media availability or time.
    pub fn page(
        &self,
        cursor: Option<&HistoryCursor>,
        limit: usize,
        cx: &ReplayCx,
    ) -> Result<HistoryPage, Error> {
        checkpoint(cx)?;
        if limit == 0 || limit > 128 {
            return Err(Error::Invalid);
        }
        let (mut generation, mut after) = match cursor {
            None => (0, 0),
            Some(cursor) if Rc::ptr_eq(&self.identity, &cursor.identity) => {
                (cursor.generation, cursor.after)
            }
            Some(_) => return Err(Error::Invalid),
        };
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(limit)
            .map_err(|_| Error::Invalid)?;
        loop {
            let journal = self.journal(generation).ok_or(Error::Invalid)?;
            let page =
                journal.confirmed_page(journal.anchor(), after, limit - entries.len(), cx)?;
            if page.pending.is_some() {
                return Err(Error::Invalid);
            }
            after = page.next_after;
            entries.extend(page.entries.into_iter().map(|entry| HistoryEntry {
                generation,
                sequence: entry.sequence,
                pin: entry.pin,
            }));
            if page.has_more {
                return Ok(HistoryPage {
                    entries,
                    next: Some(HistoryCursor {
                        identity: Rc::clone(&self.identity),
                        generation,
                        after,
                    }),
                });
            }
            generation += 1;
            if generation == self.generation_count() {
                return Ok(HistoryPage {
                    entries,
                    next: None,
                });
            }
            // The first confirmation in every successor is the verified
            // boundary replay, not an additional captured segment.
            after = 3;
            if entries.len() == limit {
                return Ok(HistoryPage {
                    entries,
                    next: Some(HistoryCursor {
                        identity: Rc::clone(&self.identity),
                        generation,
                        after,
                    }),
                });
            }
        }
    }
}

impl WorkerCustody {
    /// Identity of the newest transition; this is not camera authentication.
    pub fn binding(&self) -> Binding {
        self.transitions
            .last()
            .expect("custody is nonempty")
            .binding
    }

    /// Number of retained transitions, without implying restart recovery.
    pub fn transition_count(&self) -> usize {
        self.transitions.len()
    }

    /// Verify the complete retained switch chain and bind a read-only view to
    /// the currently settled successor. This blocks mutable access until the
    /// view is dropped, does not reopen files, and verifies no media bytes.
    pub fn history<'a>(
        &'a mut self,
        current: &'a UnknownTimeJournal,
        keeper: &UnknownTimeAnchorKeeper,
        cx: &ReplayCx,
    ) -> Result<History<'a>, Error> {
        self.check(current, keeper, cx)?;
        for (index, transition) in self.transitions.iter().enumerate() {
            checkpoint(cx)?;
            if transition.previous.journal.scope() != transition.binding.scope
                || transition.previous.journal.confirmed() != Some(transition.binding.confirmed)
            {
                return Err(Error::Invalid);
            }
            let successor = if let Some(next) = self.transitions.get(index + 1) {
                &next.previous.journal
            } else {
                current
            };
            let seed = successor.confirmed_page(transition.binding.new_journal, 0, 1, cx)?;
            if seed.entries.len() != 1
                || seed.entries[0].sequence != 3
                || seed.entries[0].pin != transition.binding.confirmed
                || seed.has_more
                || seed.pending.is_some()
            {
                return Err(Error::Invalid);
            }
        }
        Ok(History {
            custody: self,
            current,
            identity: Rc::new(()),
        })
    }

    pub(crate) fn reserve_next(&mut self) -> bool {
        self.transitions.try_reserve(1).is_ok()
    }

    pub(crate) fn append(&mut self, mut newer: Self) {
        self.transitions.append(&mut newer.transitions);
    }

    pub(crate) fn check(
        &mut self,
        journal: &UnknownTimeJournal,
        keeper: &UnknownTimeAnchorKeeper,
        cx: &ReplayCx,
    ) -> Result<(), Error> {
        let (newest, older) = self.transitions.split_last_mut().ok_or(Error::Invalid)?;
        newest.check(journal, keeper, cx)?;
        let mut successor = &newest.previous;
        for transition in older.iter_mut().rev() {
            transition.check(&successor.journal, &successor.keeper, cx)?;
            successor = &transition.previous;
        }
        Ok(())
    }

    pub(crate) fn verify_settled_av(
        &mut self,
        journal: &UnknownTimeJournal,
        keeper: &UnknownTimeAnchorKeeper,
        deployment: &mut ReferenceDeployment,
        read: &dyn archive::ReadAuthority,
        retain: &dyn archive::RetainAuthority,
        limits: archive::Limits,
        objects: archive::StagedAvLimits,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<UnknownTimePin, SettledAvError> {
        self.verify_settled(journal, keeper, deployment, read, retain, limits, objects, work, cx, false)
    }

    pub(crate) fn verify_settled_video(
        &mut self,
        journal: &UnknownTimeJournal,
        keeper: &UnknownTimeAnchorKeeper,
        deployment: &mut ReferenceDeployment,
        read: &dyn archive::ReadAuthority,
        retain: &dyn archive::RetainAuthority,
        limits: archive::Limits,
        objects: archive::StagedAvLimits,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<UnknownTimePin, SettledAvError> {
        self.verify_settled(journal, keeper, deployment, read, retain, limits, objects, work, cx, true)
    }

    fn verify_settled(
        &mut self,
        journal: &UnknownTimeJournal,
        keeper: &UnknownTimeAnchorKeeper,
        deployment: &mut ReferenceDeployment,
        read: &dyn archive::ReadAuthority,
        retain: &dyn archive::RetainAuthority,
        limits: archive::Limits,
        objects: archive::StagedAvLimits,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
        video_only: bool,
    ) -> Result<UnknownTimePin, SettledAvError> {
        self.check(journal, keeper, cx).map_err(SettledAvError::History)?;
        let verify = if video_only {
            archive::verify_settled_unknown_time_video_anchored
        } else {
            archive::verify_settled_unknown_time_av_anchored
        };
        let pin = verify(
            deployment, read, retain, limits, objects, work, cx, journal, keeper,
        ).map_err(SettledAvError::Verification)?;
        self.check(journal, keeper, cx).map_err(SettledAvError::History)?;
        checkpoint(cx).map_err(SettledAvError::History)?;
        if !read.permits(pin.retention, pin.root) || !retain.permits(pin.retention, pin.root) {
            return Err(SettledAvError::Verification(
                archive::ConfirmedAvReplayError::Readback(archive::Error::Denied),
            ));
        }
        Ok(pin)
    }
}

impl WorkerTransition {
    fn check(
        &mut self,
        journal: &UnknownTimeJournal,
        keeper: &UnknownTimeAnchorKeeper,
        cx: &ReplayCx,
    ) -> Result<(), Error> {
        checkpoint(cx)?;
        if self.switch.verify_retained_head().map_err(Error::Storage)? != self.switch_head
            || self.switch.records().len() != 1
            || self.switch.records()[0] != encode(self.binding)?
            || self.previous.journal.inner.is_fenced()
            || self.previous.keeper.is_fenced()
            || self.previous.journal.anchor() != self.binding.old_journal
            || self.previous.keeper.anchor() != self.binding.old_keeper
            || self.previous.keeper.target() != self.binding.old_journal
            || journal.inner.is_fenced()
            || keeper.is_fenced()
            || journal.scope() != self.binding.scope
            || journal.pending().is_some()
            || journal.replay_pin().is_some()
            || journal.confirmed().is_none()
            || keeper.target() != journal.anchor()
            || !journal.inner.store.contains(self.binding.new_journal)
            || !keeper.inner.store.contains(self.binding.new_keeper)
        {
            return Err(Error::Invalid);
        }
        checkpoint(cx)?;
        Ok(())
    }
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

/// A replayed current history and the verified chain that leads to it.
/// This owns the reopened histories; it does not discover or pin them.
#[must_use = "retain the current histories and all prior switch custody"]
pub struct RecoveredLineage {
    current: Previous,
    custody: WorkerCustody,
}

/// Refusal to reconstruct a lineage returns all original owners.
#[must_use = "retain or reconcile both returned history and custody"]
pub struct LineageAttachmentRefusal {
    /// Why the current history and chain could not be checked.
    pub reason: Error,
    /// Original current journal and keeper.
    pub current: Previous,
    /// Original complete transition custody.
    pub custody: WorkerCustody,
}

/// Failure to recheck a settled lineage and its confirmed A/V graph.
#[derive(Debug)]
pub enum SettledAvError {
    /// Retained rollover history or replay authority could not be checked.
    History(Error),
    /// Current policy or bounded graph verification refused the root.
    Verification(archive::ConfirmedAvReplayError),
}

impl std::fmt::Display for SettledAvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::History(_) => "rollover lineage requires reconciliation",
            Self::Verification(_) => "settled A/V verification refused",
        })
    }
}
impl std::error::Error for SettledAvError {}

/// An independently reopened next transition awaiting exact-root replay.
#[must_use = "replay or reconcile the retained transition and its prior lineage"]
pub struct ChainedActive {
    prior: WorkerCustody,
    active: Active,
}

/// Why a recovered lineage could not admit another transition.
#[derive(Debug)]
pub enum ChainRecoveryError {
    /// Existing or next history, retained switch, or authority was invalid.
    History(Error),
    /// The process could not reserve space for another custody transition.
    Capacity,
}

/// Refusal retains both the established lineage and the unadmitted owners.
#[must_use = "retain or reconcile every returned history and switch"]
pub struct ChainRecoveryRefusal {
    /// Payload-free failure classification.
    pub reason: ChainRecoveryError,
    /// Current history and prior switch custody.
    pub lineage: RecoveredLineage,
    /// Candidate successor history pair.
    pub successor: Previous,
    /// Candidate switch, which may require reopening after an I/O failure.
    pub switch: PinRetainedEffectJournal,
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

/// Failure to verify and replay a rolled A/V root.
#[derive(Debug)]
pub enum AvReplayError {
    /// The retained switch or runtime authority could not be verified.
    History(Error),
    /// A/V readback or exact-root replay requires reconciliation.
    Replay(archive::ConfirmedAvReplayError),
    /// The root was not already ledgered; preserve the actual receipt.
    UnexpectedReceipt(Box<RootLedgerReceipt>),
}

/// Failure to verify and replay a rolled video-only root.
pub type VideoReplayError = AvReplayError;
impl std::fmt::Display for AvReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::History(_) => "rollover history requires reconciliation",
            Self::Replay(_) => "rollover A/V replay requires reconciliation",
            Self::UnexpectedReceipt(_) => "rollover A/V root was not already ledgered",
        })
    }
}
impl std::error::Error for AvReplayError {}

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

fn checked_switch(switch: &mut PinRetainedEffectJournal, cx: &ReplayCx) -> Result<SwitchObservation, Error> {
    checkpoint(cx)?;
    let head = switch.verify_retained_head().map_err(Error::Storage)?;
    if switch.records().len() != 1 || head.sequence != 1 {
        return Err(Error::Invalid);
    }
    let binding = decode(&switch.records()[0])?;
    checkpoint(cx)?;
    Ok(SwitchObservation { binding, head })
}

/// Inspect a caller-opened candidate switch under explicit scope and work bounds.
///
/// This performs retainer I/O and belongs on a drained blocking worker. The
/// supplied switch must already be opened at a retained minimum and reconciled
/// with its pin retainer. A successful observation does not establish that the
/// supplied storage is independent, that no competing switch exists, or that
/// either history is available: use `recover` or `RecoveredLineage::advance`
/// to verify those histories and replay the exact root before recording.
pub fn inspect_switch(
    switch: &mut PinRetainedEffectJournal,
    expected_scope: ContentDigest,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<SwitchObservation, SwitchInspectionError> {
    checkpoint(cx).map_err(SwitchInspectionError::History)?;
    if !valid_digest(expected_scope) || switch.records().len() != 1
        || switch.records()[0].len() > MAX_SWITCH_BYTES
    {
        return Err(SwitchInspectionError::History(Error::Invalid));
    }
    let cost = u64::try_from(switch.records()[0].len())
        .ok().and_then(|n| n.checked_mul(16)).and_then(|n| n.checked_add(130))
        .ok_or(SwitchInspectionError::History(Error::Invalid))?;
    work.charge(cost).map_err(SwitchInspectionError::Work)?;
    let observation = checked_switch(switch, cx).map_err(SwitchInspectionError::History)?;
    if observation.binding.scope != expected_scope {
        return Err(SwitchInspectionError::ScopeMismatch);
    }
    checkpoint(cx).map_err(SwitchInspectionError::History)?;
    if switch.verify_retained_head().map_err(|e| SwitchInspectionError::History(Error::Storage(e)))? != observation.head {
        return Err(SwitchInspectionError::History(Error::Invalid));
    }
    checkpoint(cx).map_err(SwitchInspectionError::History)?;
    Ok(observation)
}

/// Find a unique matching transition among the supplied retained switches.
///
/// Every candidate is checked, including those which do not match. The caller
/// must establish that this bounded slice covers the relevant reservation
/// inventory and retains its freshness; `None` does not prove no omitted
/// switch exists. Matching remains a candidate claim until the histories are
/// recovered and replayed. The caller must also exclude concurrent writers;
/// these per-candidate checks do not form an atomic storage snapshot. This
/// synchronous I/O belongs on a drained worker.
pub fn select_successor_switch(
    predecessor: SwitchPredecessor,
    candidates: &mut [PinRetainedEffectJournal],
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<Option<SelectedSwitch>, SwitchSelectionError> {
    if candidates.len() > 128 {
        return Err(SwitchSelectionError::Limit);
    }
    checkpoint(cx).map_err(SwitchSelectionError::History)?;
    if !valid_digest(predecessor.scope) || !valid_digest(predecessor.confirmed.root)
        || !valid_digest(predecessor.confirmed.retention) || predecessor.journal.sequence == 0
        || predecessor.keeper.sequence == 0 || !valid_digest(predecessor.journal.root)
        || !valid_digest(predecessor.keeper.root)
    {
        return Err(SwitchSelectionError::History(Error::Invalid));
    }
    let mut selected = None;
    for (index, candidate) in candidates.iter_mut().enumerate() {
        let observation = inspect_switch(candidate, predecessor.scope, work, cx)
            .map_err(|reason| SwitchSelectionError::Candidate { index, reason })?;
        let binding = observation.binding;
        if binding.confirmed == predecessor.confirmed
            && binding.old_journal == predecessor.journal
            && binding.old_keeper == predecessor.keeper
        {
            if selected.is_some() {
                return Err(SwitchSelectionError::Ambiguous);
            }
            selected = Some(SelectedSwitch { index, observation });
        }
    }
    if let Some(chosen) = selected {
        let observed = inspect_switch(&mut candidates[chosen.index], predecessor.scope, work, cx)
            .map_err(|reason| SwitchSelectionError::Candidate { index: chosen.index, reason })?;
        if observed != chosen.observation {
            return Err(SwitchSelectionError::Candidate {
                index: chosen.index, reason: SwitchInspectionError::History(Error::Invalid),
            });
        }
    }
    checkpoint(cx).map_err(SwitchSelectionError::History)?;
    Ok(selected)
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
    switch: PinRetainedEffectJournal,
    heads: SuccessorHeads,
    cx: &ReplayCx,
) -> Result<Active, RecoveryRefusal> {
    recover_inner(previous, successor, switch, heads, cx, false)
}

fn recover_inner(
    previous: Previous,
    successor: Previous,
    mut switch: PinRetainedEffectJournal,
    heads: SuccessorHeads,
    cx: &ReplayCx,
    previous_replayed: bool,
) -> Result<Active, RecoveryRefusal> {
    let checked = (|| {
        let SwitchObservation { binding, head: switch_head } = checked_switch(&mut switch, cx)?;
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
            || old.replay_pin()
                != if previous_replayed {
                    None
                } else {
                    Some(binding.confirmed)
                }
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

impl RecoveredLineage {
    pub(crate) fn checked_scope(&mut self, cx: &ReplayCx) -> Result<ContentDigest, Error> {
        self.custody.check(&self.current.journal, &self.current.keeper, cx)?;
        Ok(self.current.journal.scope())
    }

    /// Reconstitute a settled lineage from an idle worker's exact owners.
    /// This checks the chain but does not independently locate or authenticate it.
    pub fn from_worker_parts(
        current: Previous,
        mut custody: WorkerCustody,
        cx: &ReplayCx,
    ) -> Result<Self, LineageAttachmentRefusal> {
        if let Err(reason) = custody.check(&current.journal, &current.keeper, cx) {
            return Err(LineageAttachmentRefusal { reason, current, custody });
        }
        Ok(Self { current, custody })
    }

    /// Count transitions actually retained in this in-memory lineage.
    pub fn transition_count(&self) -> usize {
        self.custody.transition_count()
    }

    /// Recheck this complete lineage and its settled A/V graph without replay.
    /// This does not locate the latest generation, authenticate the camera,
    /// or create a publication receipt. All owners remain in this lineage.
    pub fn verify_confirmed_av(
        &mut self,
        deployment: &mut ReferenceDeployment,
        read: &dyn archive::ReadAuthority,
        retain: &dyn archive::RetainAuthority,
        limits: archive::Limits,
        objects: archive::StagedAvLimits,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<UnknownTimePin, SettledAvError> {
        self.custody.verify_settled_av(
            &self.current.journal, &self.current.keeper, deployment, read, retain,
            limits, objects, work, cx,
        )
    }

    /// Return the current history and every prior switch owner for a worker.
    pub fn into_parts(self) -> (Previous, WorkerCustody) {
        (self.current, self.custody)
    }

    /// Admit the next independently reopened switch without duplicating the
    /// intermediate history. The current exact root must already be replayed.
    pub fn advance(
        mut self,
        successor: Previous,
        switch: PinRetainedEffectJournal,
        heads: SuccessorHeads,
        cx: &ReplayCx,
    ) -> Result<ChainedActive, ChainRecoveryRefusal> {
        if let Err(error) = self
            .custody
            .check(&self.current.journal, &self.current.keeper, cx)
        {
            return Err(ChainRecoveryRefusal {
                reason: ChainRecoveryError::History(error),
                lineage: self,
                successor,
                switch,
            });
        }
        if !self.custody.reserve_next() {
            return Err(ChainRecoveryRefusal {
                reason: ChainRecoveryError::Capacity,
                lineage: self,
                successor,
                switch,
            });
        }
        let Self { current, custody } = self;
        match recover_inner(current, successor, switch, heads, cx, true) {
            Ok(active) => Ok(ChainedActive {
                prior: custody,
                active,
            }),
            Err(refusal) => Err(ChainRecoveryRefusal {
                reason: ChainRecoveryError::History(refusal.reason),
                lineage: Self {
                    current: refusal.previous,
                    custody,
                },
                successor: refusal.successor,
                switch: refusal.switch,
            }),
        }
    }
}

impl ChainedActive {
    /// Transition identity, which does not authenticate a physical camera.
    pub fn binding(&self) -> Binding {
        self.active.binding()
    }

    /// Recheck the older lineage, then replay the exact successor source root.
    pub fn replay_confirmed_source(
        &mut self,
        deployment: &mut ReferenceDeployment,
        camera_claim: ContentDigest,
        read: &dyn archive::ReadAuthority,
        retain: &dyn archive::RetainAuthority,
        limits: archive::Limits,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<RootLedgerReceipt, SourceReplayError> {
        self.active
            .check_prior(&mut self.prior, cx)
            .map_err(SourceReplayError::History)?;
        self.active.replay_confirmed_source(
            deployment,
            camera_claim,
            read,
            retain,
            limits,
            work,
            cx,
        )
    }

    /// Recheck the older lineage, then replay the exact successor A/V root.
    pub fn replay_confirmed_av(
        &mut self,
        deployment: &mut ReferenceDeployment,
        read: &dyn archive::ReadAuthority,
        retain: &dyn archive::RetainAuthority,
        limits: archive::Limits,
        object_limits: archive::StagedAvLimits,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<RootLedgerReceipt, AvReplayError> {
        self.active
            .check_prior(&mut self.prior, cx)
            .map_err(AvReplayError::History)?;
        self.active
            .replay_confirmed_av(deployment, read, retain, limits, object_limits, work, cx)
    }

    /// Recheck the older lineage, then replay the exact successor video root.
    pub fn replay_confirmed_video(
        &mut self,
        deployment: &mut ReferenceDeployment,
        read: &dyn archive::ReadAuthority,
        retain: &dyn archive::RetainAuthority,
        limits: archive::Limits,
        object_limits: archive::StagedAvLimits,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<RootLedgerReceipt, VideoReplayError> {
        self.active
            .check_prior(&mut self.prior, cx)
            .map_err(AvReplayError::History)?;
        self.active.replay_confirmed_video(
            deployment,
            read,
            retain,
            limits,
            object_limits,
            work,
            cx,
        )
    }

    /// Finish only after replay and a fresh verification of every older switch.
    pub fn into_recovered_lineage(mut self, cx: &ReplayCx) -> Result<RecoveredLineage, Self> {
        if self.active.check_prior(&mut self.prior, cx).is_err() {
            return Err(self);
        }
        let Self { mut prior, active } = self;
        let (journal, keeper, custody) = match active.into_worker_parts(cx) {
            Ok(parts) => parts,
            Err(active) => return Err(Self { prior, active }),
        };
        prior.append(custody);
        Ok(RecoveredLineage {
            current: Previous { journal, keeper },
            custody: prior,
        })
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

    /// Abandon an uncommitted candidate and return the unchanged predecessor.
    /// Candidate stores may remain on disk and must be inspected by the caller.
    pub fn abort(self) -> Previous {
        self.previous
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

    /// Verify and replay the exact ledgered A/V root after rollover.
    /// Success clears only the in-memory replay fence; it does not rebuild
    /// muxer state, authenticate the camera, or establish coverage or time.
    pub fn replay_confirmed_av(
        &mut self,
        deployment: &mut ReferenceDeployment,
        read: &dyn archive::ReadAuthority,
        retain: &dyn archive::RetainAuthority,
        limits: archive::Limits,
        object_limits: archive::StagedAvLimits,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<RootLedgerReceipt, AvReplayError> {
        checkpoint(cx).map_err(AvReplayError::History)?;
        let head = self
            .switch
            .verify_retained_head()
            .map_err(|e| AvReplayError::History(Error::Storage(e)))?;
        if head != self.switch_head
            || self.switch.records().len() != 1
            || self.switch.records()[0] != encode(self.binding).map_err(AvReplayError::History)?
        {
            return Err(AvReplayError::History(Error::Invalid));
        }
        let pin = self
            .next_journal
            .confirmed()
            .ok_or(AvReplayError::History(Error::Invalid))?;
        let receipt = archive::replay_confirmed_unknown_time_av_anchored(
            deployment,
            read,
            retain,
            limits,
            object_limits,
            work,
            cx,
            &mut self.next_journal,
            &mut self.next_keeper,
        )
        .map_err(AvReplayError::Replay)?;
        if receipt.outcome != RootLedgerOutcome::AlreadyLedgered {
            self.next_journal.inner.replay_pin = Some(pin.access_pin());
            return Err(AvReplayError::UnexpectedReceipt(Box::new(receipt)));
        }
        Ok(receipt)
    }

    /// Verify and replay the exact ledgered video-only root after rollover.
    /// This clears only the in-memory replay fence and proves no camera or
    /// capture-time claim.
    pub fn replay_confirmed_video(
        &mut self,
        deployment: &mut ReferenceDeployment,
        read: &dyn archive::ReadAuthority,
        retain: &dyn archive::RetainAuthority,
        limits: archive::Limits,
        object_limits: archive::StagedAvLimits,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<RootLedgerReceipt, VideoReplayError> {
        checkpoint(cx).map_err(AvReplayError::History)?;
        let head = self
            .switch
            .verify_retained_head()
            .map_err(|e| AvReplayError::History(Error::Storage(e)))?;
        if head != self.switch_head
            || self.switch.records().len() != 1
            || self.switch.records()[0] != encode(self.binding).map_err(AvReplayError::History)?
        {
            return Err(AvReplayError::History(Error::Invalid));
        }
        let pin = self
            .next_journal
            .confirmed()
            .ok_or(AvReplayError::History(Error::Invalid))?;
        let receipt = archive::replay_confirmed_unknown_time_video_anchored(
            deployment,
            read,
            retain,
            limits,
            object_limits,
            work,
            cx,
            &mut self.next_journal,
            &mut self.next_keeper,
        )
        .map_err(AvReplayError::Replay)?;
        if receipt.outcome != RootLedgerOutcome::AlreadyLedgered {
            self.next_journal.inner.replay_pin = Some(pin.access_pin());
            return Err(AvReplayError::UnexpectedReceipt(Box::new(receipt)));
        }
        Ok(receipt)
    }

    /// Transfer the successor only after verified replay, retaining its prior
    /// histories and switch in a guard which must accompany the worker.
    pub(crate) fn into_worker_parts(
        self,
        cx: &ReplayCx,
    ) -> Result<(UnknownTimeJournal, UnknownTimeAnchorKeeper, WorkerCustody), Self> {
        let mut transitions = Vec::new();
        if transitions.try_reserve_exact(1).is_err() {
            return Err(self);
        }
        let Self {
            previous,
            next_journal,
            next_keeper,
            switch,
            binding,
            switch_head,
        } = self;
        let mut transition = WorkerTransition {
            previous,
            switch,
            binding,
            switch_head,
        };
        if transition.check(&next_journal, &next_keeper, cx).is_err() {
            return Err(Self {
                previous: transition.previous,
                next_journal,
                next_keeper,
                switch: transition.switch,
                binding,
                switch_head,
            });
        }
        transitions.push(transition);
        Ok((next_journal, next_keeper, WorkerCustody { transitions }))
    }

    /// Start a recovered lineage after the exact successor root was replayed.
    /// A refused conversion returns the complete active transition unchanged.
    pub fn into_recovered_lineage(self, cx: &ReplayCx) -> Result<RecoveredLineage, Self> {
        let (journal, keeper, custody) = self.into_worker_parts(cx)?;
        Ok(RecoveredLineage {
            current: Previous { journal, keeper },
            custody,
        })
    }

    pub(crate) fn check_prior(
        &self,
        prior: &mut WorkerCustody,
        cx: &ReplayCx,
    ) -> Result<(), Error> {
        prior.check(&self.previous.journal, &self.previous.keeper, cx)
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
