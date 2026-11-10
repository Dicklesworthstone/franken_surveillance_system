//! Explicit storage capability for restart-safe runtime effects.
//!
//! Storage retains inert canonical history, never a live grant, lease or dispatch
//! permit. The runtime validates the complete semantic history when reopening it.
//! Implementations own their I/O authority, exclusive writer and separate bounded
//! storage/read allowance. They must stop after an ambiguous append until reopened.

use fss_core::ContentDigest;

/// Journal-backed checkpoint custody with an independently retained bootstrap.
pub mod keeper;

/// Hard ceiling for one canonical runtime effect record, before storage framing.
pub const MAX_EFFECT_RECORD_BYTES: usize = 512 * 1024;
/// Hard ceiling for the complete replay history. No automatic pruning is allowed.
pub const MAX_EFFECT_HISTORY_RECORDS: usize = 65_536;

/// Independently retainable commitment to a journal prefix; this is not authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectJournalPin {
    /// One-based committed record sequence.
    pub sequence: u64,
    /// Digest of the complete storage envelope at this sequence.
    pub root: ContentDigest,
}

/// Persistence or recovery refused without granting permission to redispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectPersistenceError {
    /// The explicit storage capability refused an operation.
    Storage(String),
    /// A record violates canonical encoding or the runtime effect state machine.
    InvalidHistory(&'static str),
    /// The independent minimum commitment is absent from the verified history.
    PinMismatch,
    /// A prior write may have committed; only a cold reopen can classify it.
    Poisoned,
    /// The complete history or next record exceeds a declared hard bound.
    Capacity,
}

impl std::fmt::Display for EffectPersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(detail) => write!(f, "runtime effect storage: {detail}"),
            Self::InvalidHistory(detail) => write!(f, "invalid runtime effect history: {detail}"),
            Self::PinMismatch => f.write_str("runtime effect journal minimum pin is absent"),
            Self::Poisoned => f.write_str("runtime effect journal requires cold recovery"),
            Self::Capacity => f.write_str("runtime effect journal capacity exceeded"),
        }
    }
}

impl std::error::Error for EffectPersistenceError {}

/// Exclusive, bounded compare-and-append storage of complete effect history.
///
/// `records()` contains every committed payload in sequence order, excluding
/// storage envelopes and incomplete staging. Success from `append` means the
/// complete record and its discoverable name are durable and read back. The
/// current head, contiguous history and original namespace must remain verified;
/// a stale cached head alone cannot authorize an append. Physical rollback is
/// detectable only through the caller's independently retained minimum pin.
pub trait EffectJournalStore: std::fmt::Debug + Send + Sync {
    /// Current verified head, or none for a completely empty store.
    fn head(&self) -> Option<EffectJournalPin>;
    /// Complete verified payload history. Returning a suffix is forbidden.
    fn records(&self) -> &[Vec<u8>];
    /// Whether this exact pin belongs to the complete verified chain.
    fn contains(&self, pin: EffectJournalPin) -> bool;
    /// Preflight space for the next record and its bounded follow-up records.
    /// Refusal must precede writes and must not poison an unchanged store.
    fn reserve_capacity(
        &mut self,
        additional_records: usize,
        max_record_bytes: usize,
    ) -> Result<(), EffectPersistenceError>;
    /// Persist one payload only if the head still equals `expected`.
    /// Any ambiguous failure must disable this writer until cold reopen.
    fn append(
        &mut self,
        expected: Option<EffectJournalPin>,
        record: &[u8],
    ) -> Result<EffectJournalPin, EffectPersistenceError>;
}

/// Separately owned custody for acknowledged effect-journal prefixes.
///
/// An implementation must use an explicitly supplied storage authority and a
/// failure domain suitable for the owner's threat model. It must durably retain
/// and read back `next` before `retain` succeeds, and must compare `expected`
/// against the current retained value. An error may follow a successful write;
/// the caller must then stop and recover rather than retry. Neither this trait
/// nor the runtime can establish that a supplied implementation is independent
/// of the effect journal, protected from rollback, or available after a crash.
pub trait EffectPinRetainer: std::fmt::Debug + Send + Sync {
    /// Read the currently retained commitment from the owner's custody domain.
    fn retained_pin(&mut self) -> Result<Option<EffectJournalPin>, EffectPersistenceError>;

    /// Refuse insufficient capacity before writing; this must not change custody.
    fn reserve_capacity(&mut self, additional_pins: usize) -> Result<(), EffectPersistenceError>;

    /// Verify retained target commitments against the separately opened journal.
    /// Implementations retaining a history must check every retained target.
    /// This check does not grant authority or authenticate an external outcome.
    fn verify_effect_history(
        &mut self,
        journal: &dyn EffectJournalStore,
    ) -> Result<(), EffectPersistenceError>;

    /// Compare, durably retain and verify the next commitment.
    fn retain(
        &mut self,
        expected: Option<EffectJournalPin>,
        next: EffectJournalPin,
    ) -> Result<(), EffectPersistenceError>;
}

/// An initially empty journal whose acknowledgements require separate pin custody.
///
/// An append that may have reached either custody domain fences this owner on
/// *any* failure. A recovered coordinator still needs the independently retained
/// pin, the original journal, operation-specific evidence, and reconciliation;
/// this wrapper never recreates a permit or proves an external effect occurred.
#[derive(Debug)]
pub struct PinRetainedEffectJournal {
    journal: Box<dyn EffectJournalStore>,
    retainer: Box<dyn EffectPinRetainer>,
    retained: Option<EffectJournalPin>,
    poisoned: bool,
}

impl PinRetainedEffectJournal {
    /// Bind two empty, exclusively owned custody domains for a new history.
    /// Existing history must be handled by the explicit recovery path.
    pub fn new(
        journal: Box<dyn EffectJournalStore>,
        mut retainer: Box<dyn EffectPinRetainer>,
    ) -> Result<Self, EffectPersistenceError> {
        if journal.head().is_some() || !journal.records().is_empty() {
            return Err(EffectPersistenceError::InvalidHistory(
                "new retained journal requires empty effect history",
            ));
        }
        if retainer.retained_pin()?.is_some() {
            return Err(EffectPersistenceError::InvalidHistory(
                "new retained journal requires empty pin custody",
            ));
        }
        Ok(Self {
            journal,
            retainer,
            retained: None,
            poisoned: false,
        })
    }

    /// Bind matching, already verified custody domains for reconciliation.
    ///
    /// The journal must have been opened at an independently retained minimum,
    /// and its current head must exactly match the retainer's verified target.
    /// A later journal record or missing checkpoint is ambiguous and requires
    /// separate recovery; this method never advances either domain. Pass the
    /// returned store to `EffectCoordinator::recover`, which restores no grant,
    /// lease, or permit and does not admit new dispatches.
    pub fn for_reconciliation(
        journal: Box<dyn EffectJournalStore>,
        mut retainer: Box<dyn EffectPinRetainer>,
    ) -> Result<Self, EffectPersistenceError> {
        let retained = retainer
            .retained_pin()?
            .ok_or(EffectPersistenceError::PinMismatch)?;
        if retained.sequence == 0
            || retained.root.is_laboratory()
            || journal.head() != Some(retained)
            || !journal.contains(retained)
            || retained.sequence as u128 != journal.records().len() as u128
        {
            return Err(EffectPersistenceError::PinMismatch);
        }
        retainer.verify_effect_history(journal.as_ref())?;
        Ok(Self {
            journal,
            retainer,
            retained: Some(retained),
            poisoned: false,
        })
    }

    /// Recheck the currently retained head against both custody domains.
    ///
    /// This performs no append and grants no effect authority. A mismatch or
    /// failure fences this owner until the journal and retainer are reopened.
    pub fn verify_retained_head(&mut self) -> Result<EffectJournalPin, EffectPersistenceError> {
        if self.poisoned {
            return Err(EffectPersistenceError::Poisoned);
        }
        let result = (|| {
            let retained = self.retained.ok_or(EffectPersistenceError::PinMismatch)?;
            if self.retainer.retained_pin()? != Some(retained)
                || self.journal.head() != Some(retained)
                || !self.journal.contains(retained)
                || retained.sequence as u128 != self.journal.records().len() as u128
            {
                return Err(EffectPersistenceError::PinMismatch);
            }
            self.retainer.verify_effect_history(self.journal.as_ref())?;
            Ok(retained)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

impl EffectJournalStore for PinRetainedEffectJournal {
    fn head(&self) -> Option<EffectJournalPin> {
        self.journal.head()
    }

    fn records(&self) -> &[Vec<u8>] {
        self.journal.records()
    }

    fn contains(&self, pin: EffectJournalPin) -> bool {
        self.journal.contains(pin)
    }

    fn reserve_capacity(
        &mut self,
        additional_records: usize,
        max_record_bytes: usize,
    ) -> Result<(), EffectPersistenceError> {
        if self.poisoned {
            return Err(EffectPersistenceError::Poisoned);
        }
        self.journal
            .reserve_capacity(additional_records, max_record_bytes)?;
        self.retainer.reserve_capacity(additional_records)
    }

    fn append(
        &mut self,
        expected: Option<EffectJournalPin>,
        record: &[u8],
    ) -> Result<EffectJournalPin, EffectPersistenceError> {
        if self.poisoned {
            return Err(EffectPersistenceError::Poisoned);
        }
        if expected != self.retained || self.journal.head() != self.retained {
            self.poisoned = true;
            return Err(EffectPersistenceError::PinMismatch);
        }
        // Callers of the store trait are not required to preflight separately.
        // Capacity refusals leave both domains untouched and do not fence.
        self.reserve_capacity(1, record.len())?;
        let result = (|| {
            if self.retainer.retained_pin()? != self.retained {
                return Err(EffectPersistenceError::PinMismatch);
            }
            let next = self.journal.append(expected, record)?;
            if Some(next.sequence) != expected.map_or(Some(1), |pin| pin.sequence.checked_add(1))
                || next.root.is_laboratory()
                || self.journal.head() != Some(next)
                || !self.journal.contains(next)
                || self.journal.records().last().map(Vec::as_slice) != Some(record)
            {
                return Err(EffectPersistenceError::InvalidHistory(
                    "retained journal append receipt",
                ));
            }
            self.retainer.retain(expected, next)?;
            if self.retainer.retained_pin()? != Some(next) {
                return Err(EffectPersistenceError::PinMismatch);
            }
            Ok(next)
        })();
        match result {
            Ok(next) => {
                self.retained = Some(next);
                Ok(next)
            }
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }
}
