#![forbid(unsafe_code)]
//! A separately supplied journal can retain effect-journal prefix commitments.
//!
//! Its bootstrap anchor must itself be retained independently before use. A
//! bootstrap minimum detects rollback before that prefix only; the caller must
//! retain later keeper anchors independently to detect later rollback. This
//! layer does not establish that two supplied stores have independent failure
//! domains, nor does it grant authority to dispatch or reconcile an effect.

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm};

use super::{
    EffectJournalPin, EffectJournalStore, EffectPersistenceError, EffectPinRetainer,
    MAX_EFFECT_HISTORY_RECORDS,
};

const DOMAIN: &str = "fss.runtime_effect_pin_keeper.v1";
const MAX_RECORD_BYTES: usize = 256;

fn valid_digest(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256
        && !digest.is_laboratory()
        && digest.bytes() != [0; 32]
}

fn encode(
    scope: ContentDigest,
    target: Option<EffectJournalPin>,
) -> Result<Vec<u8>, EffectPersistenceError> {
    if !valid_digest(scope)
        || target.is_some_and(|pin| pin.sequence == 0 || !valid_digest(pin.root))
    {
        return Err(EffectPersistenceError::InvalidHistory("invalid keeper pin"));
    }
    let mut output = CanonicalEncoder::new();
    output.text(DOMAIN);
    output.digest(scope);
    output.bool(target.is_some());
    if let Some(pin) = target {
        output.u64(pin.sequence);
        output.digest(pin.root);
    }
    let bytes = output
        .finish_checked()
        .map_err(|_| EffectPersistenceError::InvalidHistory("keeper record encoding"))?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(EffectPersistenceError::Capacity);
    }
    Ok(bytes)
}

fn decode(
    scope: ContentDigest,
    bytes: &[u8],
) -> Result<Option<EffectJournalPin>, EffectPersistenceError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(EffectPersistenceError::Capacity);
    }
    let invalid = |_| EffectPersistenceError::InvalidHistory("keeper record decoding");
    let mut input = CanonicalDecoder::new(bytes);
    if input.text().map_err(invalid)? != DOMAIN || input.digest().map_err(invalid)? != scope {
        return Err(EffectPersistenceError::InvalidHistory(
            "keeper scope or domain",
        ));
    }
    let target = if input.bool().map_err(invalid)? {
        Some(EffectJournalPin {
            sequence: input.u64().map_err(invalid)?,
            root: input.digest().map_err(invalid)?,
        })
    } else {
        None
    };
    input.ensure_finished().map_err(invalid)?;
    if encode(scope, target)? != bytes {
        return Err(EffectPersistenceError::InvalidHistory(
            "noncanonical keeper record",
        ));
    }
    Ok(target)
}

/// Retains effect pins in a dedicated, separately supplied effect-journal store.
#[derive(Debug)]
pub struct JournalPinRetainer {
    store: Box<dyn EffectJournalStore>,
    scope: ContentDigest,
    target: Option<EffectJournalPin>,
    anchor: EffectJournalPin,
    poisoned: bool,
}

impl JournalPinRetainer {
    /// Create a new keeper and return its bootstrap anchor for independent custody.
    ///
    /// The caller must retain that anchor in another trust domain *before*
    /// handing this keeper to a live effect owner. A failed append may have
    /// created history and must not be retried as a fresh keeper.
    pub fn create(
        mut store: Box<dyn EffectJournalStore>,
        scope: ContentDigest,
    ) -> Result<(Self, EffectJournalPin), EffectPersistenceError> {
        if store.head().is_some() || !store.records().is_empty() {
            return Err(EffectPersistenceError::InvalidHistory(
                "keeper store is not empty",
            ));
        }
        let bytes = encode(scope, None)?;
        store.reserve_capacity(1, MAX_RECORD_BYTES)?;
        let anchor = store.append(None, &bytes)?;
        if anchor.sequence != 1
            || !valid_digest(anchor.root)
            || store.head() != Some(anchor)
            || !store.contains(anchor)
            || store.records().len() != 1
            || store.records().last() != Some(&bytes)
        {
            return Err(EffectPersistenceError::InvalidHistory(
                "keeper bootstrap receipt",
            ));
        }
        Ok((
            Self {
                store,
                scope,
                target: None,
                anchor,
                poisoned: false,
            },
            anchor,
        ))
    }

    /// Reopen complete keeper history at an independently retained minimum.
    ///
    /// The underlying store must already have verified its physical namespace.
    /// The returned target is only a journal prefix: callers must verify it
    /// against the original effect journal and reconcile external outcomes.
    pub fn reopen(
        store: Box<dyn EffectJournalStore>,
        scope: ContentDigest,
        minimum: EffectJournalPin,
    ) -> Result<Self, EffectPersistenceError> {
        if !valid_digest(scope)
            || minimum.sequence == 0
            || !valid_digest(minimum.root)
            || !store.contains(minimum)
            || store.records().is_empty()
            || store.records().len() > MAX_EFFECT_HISTORY_RECORDS
        {
            return Err(EffectPersistenceError::PinMismatch);
        }
        let anchor = store.head().ok_or(EffectPersistenceError::PinMismatch)?;
        if !valid_digest(anchor.root)
            || anchor.sequence as u128 != store.records().len() as u128
            || !store.contains(anchor)
        {
            return Err(EffectPersistenceError::InvalidHistory(
                "keeper history incomplete",
            ));
        }
        let mut target = None;
        for (index, bytes) in store.records().iter().enumerate() {
            let next = decode(scope, bytes)?;
            if index == 0 {
                if next.is_some() {
                    return Err(EffectPersistenceError::InvalidHistory(
                        "keeper bootstrap missing",
                    ));
                }
            } else if next.map(|pin| pin.sequence)
                != target.map_or(Some(1), |pin: EffectJournalPin| pin.sequence.checked_add(1))
            {
                return Err(EffectPersistenceError::InvalidHistory(
                    "keeper target sequence",
                ));
            }
            target = next;
        }
        Ok(Self {
            store,
            scope,
            target,
            anchor,
            poisoned: false,
        })
    }

    /// Last acknowledged keeper prefix, to retain in another trust domain.
    #[must_use]
    pub const fn anchor(&self) -> EffectJournalPin {
        self.anchor
    }
}

impl EffectPinRetainer for JournalPinRetainer {
    fn retained_pin(&mut self) -> Result<Option<EffectJournalPin>, EffectPersistenceError> {
        if self.poisoned {
            return Err(EffectPersistenceError::Poisoned);
        }
        if self.store.head() != Some(self.anchor)
            || !self.store.contains(self.anchor)
            || self.store.records().last().map(Vec::as_slice)
                != Some(encode(self.scope, self.target)?.as_slice())
        {
            self.poisoned = true;
            return Err(EffectPersistenceError::PinMismatch);
        }
        Ok(self.target)
    }

    fn reserve_capacity(&mut self, additional_pins: usize) -> Result<(), EffectPersistenceError> {
        if self.poisoned {
            return Err(EffectPersistenceError::Poisoned);
        }
        self.store
            .reserve_capacity(additional_pins, MAX_RECORD_BYTES)
    }

    fn retain(
        &mut self,
        expected: Option<EffectJournalPin>,
        next: EffectJournalPin,
    ) -> Result<(), EffectPersistenceError> {
        if self.retained_pin()? != expected
            || Some(next.sequence) != expected.map_or(Some(1), |pin| pin.sequence.checked_add(1))
        {
            self.poisoned = true;
            return Err(EffectPersistenceError::PinMismatch);
        }
        let bytes = encode(self.scope, Some(next))?;
        self.store.reserve_capacity(1, MAX_RECORD_BYTES)?;
        let result = self.store.append(Some(self.anchor), &bytes);
        match result {
            Ok(anchor)
                if self.anchor.sequence.checked_add(1) == Some(anchor.sequence)
                    && valid_digest(anchor.root)
                    && self.store.head() == Some(anchor)
                    && self.store.contains(anchor)
                    && anchor.sequence as u128 == self.store.records().len() as u128
                    && self.store.records().last() == Some(&bytes) =>
            {
                self.anchor = anchor;
                self.target = Some(next);
                Ok(())
            }
            Ok(_) => {
                self.poisoned = true;
                Err(EffectPersistenceError::InvalidHistory(
                    "keeper append receipt",
                ))
            }
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }
}
