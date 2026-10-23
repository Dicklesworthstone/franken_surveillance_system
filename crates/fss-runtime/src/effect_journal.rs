//! Explicit storage capability for restart-safe runtime effects.
//!
//! Storage retains inert canonical history, never a live grant, lease or dispatch
//! permit. The runtime validates the complete semantic history when reopening it.
//! Implementations own their I/O authority, exclusive writer and separate bounded
//! storage/read allowance. They must stop after an ambiguous append until reopened.

use fss_core::ContentDigest;

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
