#![forbid(unsafe_code)]
//! Independent, bounded metadata history for UniFi archive publication intents.
//!
//! This journal retains pins, not media, muxer state, grants, or camera identity.
//! A separately owned `EffectJournalStore` supplies exclusive durable storage;
//! it must be dedicated to this domain and reopened with an independent minimum
//! storage pin. Every I/O operation remains subject to the caller's `ReplayCx`.

use fss_core::{
    CanonicalDecoder, CanonicalEncoder, CaptureInterval, ContentDigest, DigestAlgorithm,
    TimestampNs,
};
use fss_runtime::effect_journal::{EffectJournalPin, EffectJournalStore, EffectPersistenceError};

use super::{Pin, UnknownTimePin};
use crate::ReplayCx;

const DOMAIN: &str = "fss.unifi-direct.av-publication-intent.v1";
const UNKNOWN_TIME_DOMAIN: &str = "fss.unifi-direct.av-unknown-time-intent.v1";
const MAX_RECORD_BYTES: usize = 256;
const MAX_RECORDS: usize = 16_384;
const ANCHOR_DOMAIN: &str = "fss.unifi-direct.av-publication-anchor.v1";

/// A refusal leaves any candidate root unresolved. Storage errors can be
/// indeterminate and require cold reopening at the last independent anchor.
#[derive(Debug)]
pub enum Error {
    /// Storage failed or must be reopened after an uncertain append.
    Storage(EffectPersistenceError),
    /// History, scope, root, or state is not the expected canonical value.
    Invalid,
    /// The runtime authority or cancellation checkpoint refused progress.
    Cancelled,
    /// This owner cannot append after an uncertain storage result.
    Fenced,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Storage(_) => "publication intent journal requires recovery",
            Self::Invalid => "publication intent journal history or scope invalid",
            Self::Cancelled => "publication intent journal authority withdrawn",
            Self::Fenced => "publication intent journal owner fenced",
        })
    }
}
impl std::error::Error for Error {}

/// Exclusive semantic owner for a dedicated publication-intent store.
pub struct Journal {
    store: Box<dyn EffectJournalStore>,
    domain: &'static str,
    scope: ContentDigest,
    pending: Option<Pin>,
    confirmed: Option<Pin>,
    fenced: bool,
    acknowledged: EffectJournalPin,
    replay_pin: Option<Pin>,
}
impl std::fmt::Debug for Journal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicationIntentJournal")
            .field("scope", &self.scope)
            .field("pending", &self.pending)
            .field("confirmed", &self.confirmed)
            .field("replay_pin", &self.replay_pin)
            .field("fenced", &self.fenced)
            .finish_non_exhaustive()
    }
}

fn valid_digest(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256
        && !digest.is_laboratory()
        && digest.bytes() != [0; 32]
}
fn valid_pin(pin: Pin) -> bool {
    valid_digest(pin.root)
        && valid_digest(pin.retention)
        && pin.capture.earliest <= pin.capture.latest
}
fn checkpoint(cx: &ReplayCx) -> Result<(), Error> {
    cx.checkpoint("unifi-av-publication-journal")
        .map_err(|_| Error::Cancelled)
}
fn encode(
    domain: &str,
    scope: ContentDigest,
    kind: u8,
    pin: Option<Pin>,
) -> Result<Vec<u8>, Error> {
    let mut out = CanonicalEncoder::new();
    out.text(domain);
    out.digest(scope);
    out.u8(kind);
    if let Some(pin) = pin {
        out.digest(pin.root);
        out.digest(pin.retention);
        out.i128(pin.capture.earliest.0);
        out.i128(pin.capture.latest.0);
    }
    let bytes = out.finish_checked().map_err(|_| Error::Invalid)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}
fn decode(bytes: &[u8], domain: &str, scope: ContentDigest) -> Result<(u8, Option<Pin>), Error> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(Error::Invalid);
    }
    let mut input = CanonicalDecoder::new(bytes);
    if input.text().map_err(|_| Error::Invalid)? != domain
        || input.digest().map_err(|_| Error::Invalid)? != scope
    {
        return Err(Error::Invalid);
    }
    let kind = input.u8().map_err(|_| Error::Invalid)?;
    let pin = match kind {
        0 => None,
        1 | 2 => {
            let root = input.digest().map_err(|_| Error::Invalid)?;
            let retention = input.digest().map_err(|_| Error::Invalid)?;
            let earliest = TimestampNs(input.i128().map_err(|_| Error::Invalid)?);
            let latest = TimestampNs(input.i128().map_err(|_| Error::Invalid)?);
            let capture = CaptureInterval::new(earliest, latest).map_err(|_| Error::Invalid)?;
            let pin = Pin {
                root,
                retention,
                capture,
            };
            if !valid_pin(pin) {
                return Err(Error::Invalid);
            }
            Some(pin)
        }
        _ => return Err(Error::Invalid),
    };
    input.ensure_finished().map_err(|_| Error::Invalid)?;
    Ok((kind, pin))
}

impl Journal {
    /// Initialize a dedicated empty store with an immutable caller-selected scope.
    /// Retain the returned anchor independently before allowing publication.
    pub fn create(
        store: Box<dyn EffectJournalStore>,
        scope: ContentDigest,
        cx: &ReplayCx,
    ) -> Result<Self, Error> {
        Self::create_in_domain(store, scope, cx, DOMAIN)
    }

    fn create_in_domain(
        mut store: Box<dyn EffectJournalStore>,
        scope: ContentDigest,
        cx: &ReplayCx,
        domain: &'static str,
    ) -> Result<Self, Error> {
        if !valid_digest(scope) || store.head().is_some() || !store.records().is_empty() {
            return Err(Error::Invalid);
        }
        checkpoint(cx)?;
        store
            .reserve_capacity(1, MAX_RECORD_BYTES)
            .map_err(Error::Storage)?;
        let bytes = encode(domain, scope, 0, None)?;
        let acknowledged = store.append(None, &bytes).map_err(Error::Storage)?;
        if acknowledged.sequence != 1 || !valid_digest(acknowledged.root) {
            return Err(Error::Invalid);
        }
        Ok(Self {
            store,
            domain,
            scope,
            pending: None,
            confirmed: None,
            fenced: false,
            acknowledged,
            replay_pin: None,
        })
    }

    /// Replay complete storage history anchored to a separately retained pin.
    /// A valid pin detects rollback before that prefix, not later rollback.
    pub fn reopen(
        store: Box<dyn EffectJournalStore>,
        scope: ContentDigest,
        minimum: EffectJournalPin,
        cx: &ReplayCx,
    ) -> Result<Self, Error> {
        Self::reopen_in_domain(store, scope, minimum, cx, DOMAIN)
    }

    fn reopen_in_domain(
        store: Box<dyn EffectJournalStore>,
        scope: ContentDigest,
        minimum: EffectJournalPin,
        cx: &ReplayCx,
        domain: &'static str,
    ) -> Result<Self, Error> {
        checkpoint(cx)?;
        if !valid_digest(scope)
            || !store.contains(minimum)
            || store.records().is_empty()
            || store.records().len() > MAX_RECORDS
        {
            return Err(Error::Invalid);
        }
        let mut pending = None;
        let mut confirmed = None;
        for (index, bytes) in store.records().iter().enumerate() {
            checkpoint(cx)?;
            let (kind, pin) = decode(bytes, domain, scope)?;
            if domain == UNKNOWN_TIME_DOMAIN
                && pin.is_some_and(|p| p.capture != super::unknown_ledger_validity())
            {
                return Err(Error::Invalid);
            }
            match (index, kind, pin) {
                (0, 0, None) => {}
                (0, _, _) | (_, 0, _) => return Err(Error::Invalid),
                (_, 1, Some(pin)) if pending.is_none() => pending = Some(pin),
                (_, 2, Some(pin)) if pending == Some(pin) => {
                    pending = None;
                    confirmed = Some(pin);
                }
                _ => return Err(Error::Invalid),
            }
        }
        let acknowledged = store.head().ok_or(Error::Invalid)?;
        if acknowledged.sequence
            != u64::try_from(store.records().len()).map_err(|_| Error::Invalid)?
            || !valid_digest(acknowledged.root)
            || !store.contains(acknowledged)
        {
            return Err(Error::Invalid);
        }
        let replay_pin = pending.or(confirmed);
        Ok(Self {
            store,
            domain,
            scope,
            pending,
            confirmed,
            fenced: false,
            acknowledged,
            replay_pin,
        })
    }

    /// Last acknowledged durable storage prefix, for independent retention.
    pub fn anchor(&self) -> EffectJournalPin {
        self.acknowledged
    }
    /// Caller-selected immutable scope; it does not authenticate a camera.
    pub fn scope(&self) -> ContentDigest {
        self.scope
    }
    /// Root whose publication may have happened and requires reconciliation.
    pub fn pending(&self) -> Option<Pin> {
        self.pending
    }
    /// Last root whose archive receipt was journaled.
    pub fn confirmed(&self) -> Option<Pin> {
        self.confirmed
    }

    /// After cold reopening, this exact root must be replayed before this
    /// journal admits a different root. Source and prior muxer state remain
    /// the caller's separate reconstruction responsibility.
    pub fn replay_pin(&self) -> Option<Pin> {
        self.replay_pin
    }

    pub(super) fn is_fenced(&self) -> bool {
        self.fenced
    }

    fn append(&mut self, kind: u8, pin: Pin, cx: &ReplayCx) -> Result<(), Error> {
        if self.fenced {
            return Err(Error::Fenced);
        }
        checkpoint(cx)?;
        if self.store.records().len() >= MAX_RECORDS {
            return Err(Error::Invalid);
        }
        let bytes = encode(self.domain, self.scope, kind, Some(pin))?;
        let expected = self.acknowledged;
        let next = match self.store.append(Some(expected), &bytes) {
            Ok(next) => next,
            Err(error) => {
                self.fenced = true;
                return Err(Error::Storage(error));
            }
        };
        if expected.sequence.checked_add(1) != Some(next.sequence) || !valid_digest(next.root) {
            self.fenced = true;
            return Err(Error::Invalid);
        }
        self.acknowledged = next;
        Ok(())
    }

    pub(super) fn prepare(&mut self, pin: Pin, cx: &ReplayCx) -> Result<(), Error> {
        if self.fenced {
            return Err(Error::Fenced);
        }
        if !valid_pin(pin) {
            return Err(Error::Invalid);
        }
        if self.replay_pin.is_some_and(|expected| expected != pin) {
            return Err(Error::Invalid);
        }
        if let Some(pending) = self.pending {
            return if pending == pin {
                Ok(())
            } else {
                Err(Error::Invalid)
            };
        }
        if self.confirmed == Some(pin) {
            return Ok(());
        }
        if self
            .store
            .records()
            .len()
            .checked_add(2)
            .is_none_or(|count| count > MAX_RECORDS)
        {
            return Err(Error::Invalid);
        }
        checkpoint(cx)?;
        // Reserve both candidate and confirmation before any archive effect.
        self.store
            .reserve_capacity(2, MAX_RECORD_BYTES)
            .map_err(Error::Storage)?;
        self.append(1, pin, cx)?;
        self.pending = Some(pin);
        Ok(())
    }

    pub(super) fn confirm(&mut self, pin: Pin, cx: &ReplayCx) -> Result<(), Error> {
        if self.fenced {
            return Err(Error::Fenced);
        }
        if self.pending.is_none() && self.confirmed == Some(pin) {
            self.replay_pin = None;
            return Ok(());
        }
        if self.pending != Some(pin) {
            return Err(Error::Invalid);
        }
        self.append(2, pin, cx)?;
        self.pending = None;
        self.confirmed = Some(pin);
        self.replay_pin = None;
        Ok(())
    }
}

/// Exclusive publication-intent history for explicitly unknown capture time.
/// Its domain is distinct from [`Journal`]; no physical capture interval is
/// exposed by its pins. Media and muxer state remain separately owned.
pub struct UnknownTimeJournal {
    pub(super) inner: Journal,
}
impl UnknownTimeJournal {
    /// Create a dedicated empty unknown-time journal.
    pub fn create(
        store: Box<dyn EffectJournalStore>,
        scope: ContentDigest,
        cx: &ReplayCx,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: Journal::create_in_domain(store, scope, cx, UNKNOWN_TIME_DOMAIN)?,
        })
    }

    /// Reopen verified history against an independently retained minimum.
    pub fn reopen(
        store: Box<dyn EffectJournalStore>,
        scope: ContentDigest,
        minimum: EffectJournalPin,
        cx: &ReplayCx,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: Journal::reopen_in_domain(store, scope, minimum, cx, UNKNOWN_TIME_DOMAIN)?,
        })
    }

    /// Last acknowledged journal prefix, to retain independently.
    pub fn anchor(&self) -> EffectJournalPin {
        self.inner.anchor()
    }

    /// Immutable caller-selected scope, not camera authentication.
    pub fn scope(&self) -> ContentDigest {
        self.inner.scope()
    }

    /// Candidate whose outcome requires reconciliation, if any.
    pub fn pending(&self) -> Option<UnknownTimePin> {
        self.inner.pending().map(unknown_pin)
    }

    /// Last root with journaled confirmation, if any.
    pub fn confirmed(&self) -> Option<UnknownTimePin> {
        self.inner.confirmed().map(unknown_pin)
    }

    /// After reopening, the exact candidate required for deterministic replay.
    pub fn replay_pin(&self) -> Option<UnknownTimePin> {
        self.inner.replay_pin().map(unknown_pin)
    }

    pub(super) fn prepare(&mut self, pin: UnknownTimePin, cx: &ReplayCx) -> Result<(), Error> {
        self.inner.prepare(pin.access_pin(), cx)
    }

    pub(super) fn confirm(&mut self, pin: UnknownTimePin, cx: &ReplayCx) -> Result<(), Error> {
        self.inner.confirm(pin.access_pin(), cx)
    }
}

fn unknown_pin(pin: Pin) -> UnknownTimePin {
    debug_assert_eq!(pin.capture, super::unknown_ledger_validity());
    UnknownTimePin {
        root: pin.root,
        retention: pin.retention,
    }
}

/// Independent anchor history for an unknown-time publication journal.
pub struct UnknownTimeAnchorKeeper {
    inner: AnchorKeeper,
}
impl UnknownTimeAnchorKeeper {
    /// Bind a dedicated empty store to the current unknown-time journal prefix.
    pub fn create(
        store: Box<dyn EffectJournalStore>,
        journal: &UnknownTimeJournal,
        cx: &ReplayCx,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: AnchorKeeper::create(store, &journal.inner, cx)?,
        })
    }

    /// Reopen and verify the keeper against its independently retained minimum.
    pub fn reopen(
        store: Box<dyn EffectJournalStore>,
        journal: &UnknownTimeJournal,
        minimum: EffectJournalPin,
        cx: &ReplayCx,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: AnchorKeeper::reopen(store, &journal.inner, minimum, cx)?,
        })
    }

    /// Last acknowledged keeper prefix for independent retention.
    pub fn anchor(&self) -> EffectJournalPin {
        self.inner.anchor()
    }

    /// Latest journal prefix durably retained by this keeper.
    pub fn target(&self) -> EffectJournalPin {
        self.inner.target()
    }

    pub(super) fn is_fenced(&self) -> bool {
        self.inner.fenced
    }

    pub(super) fn retain(
        &mut self,
        journal: &UnknownTimeJournal,
        cx: &ReplayCx,
    ) -> Result<(), Error> {
        self.inner.retain(&journal.inner, cx)
    }
}

/// A separately stored chain of journal prefixes. Its own minimum pin must be
/// retained independently; this does not make two stores rollback-proof.
pub struct AnchorKeeper {
    store: Box<dyn EffectJournalStore>,
    scope: ContentDigest,
    target: EffectJournalPin,
    acknowledged: EffectJournalPin,
    fenced: bool,
}

fn encode_anchor(scope: ContentDigest, target: EffectJournalPin) -> Result<Vec<u8>, Error> {
    let mut out = CanonicalEncoder::new();
    out.text(ANCHOR_DOMAIN);
    out.digest(scope);
    out.u64(target.sequence);
    out.digest(target.root);
    let bytes = out.finish_checked().map_err(|_| Error::Invalid)?;
    if bytes.len() > MAX_RECORD_BYTES || target.sequence == 0 || !valid_digest(target.root) {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}

fn decode_anchor(bytes: &[u8], scope: ContentDigest) -> Result<EffectJournalPin, Error> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(Error::Invalid);
    }
    let mut input = CanonicalDecoder::new(bytes);
    if input.text().map_err(|_| Error::Invalid)? != ANCHOR_DOMAIN
        || input.digest().map_err(|_| Error::Invalid)? != scope
    {
        return Err(Error::Invalid);
    }
    let pin = EffectJournalPin {
        sequence: input.u64().map_err(|_| Error::Invalid)?,
        root: input.digest().map_err(|_| Error::Invalid)?,
    };
    input.ensure_finished().map_err(|_| Error::Invalid)?;
    if pin.sequence == 0 || !valid_digest(pin.root) {
        return Err(Error::Invalid);
    }
    Ok(pin)
}

impl AnchorKeeper {
    /// Create an independent, dedicated store bound to this journal's current
    /// prefix. The caller must retain the keeper's pin in another trust domain.
    pub fn create(
        mut store: Box<dyn EffectJournalStore>,
        journal: &Journal,
        cx: &ReplayCx,
    ) -> Result<Self, Error> {
        checkpoint(cx)?;
        if journal.fenced || store.head().is_some() || !store.records().is_empty() {
            return Err(Error::Invalid);
        }
        let target = journal.anchor();
        let bytes = encode_anchor(journal.scope, target)?;
        store
            .reserve_capacity(1, MAX_RECORD_BYTES)
            .map_err(Error::Storage)?;
        let acknowledged = store.append(None, &bytes).map_err(Error::Storage)?;
        if acknowledged.sequence != 1 || !valid_digest(acknowledged.root) {
            return Err(Error::Invalid);
        }
        Ok(Self {
            store,
            scope: journal.scope,
            target,
            acknowledged,
            fenced: false,
        })
    }

    /// Reopen both chains against an independently retained keeper minimum.
    /// Every retained target prefix must occur in the journal's verified chain.
    pub fn reopen(
        store: Box<dyn EffectJournalStore>,
        journal: &Journal,
        minimum: EffectJournalPin,
        cx: &ReplayCx,
    ) -> Result<Self, Error> {
        checkpoint(cx)?;
        if journal.fenced
            || !store.contains(minimum)
            || store.records().is_empty()
            || store.records().len() > MAX_RECORDS
        {
            return Err(Error::Invalid);
        }
        let mut target: Option<EffectJournalPin> = None;
        for bytes in store.records() {
            checkpoint(cx)?;
            let next = decode_anchor(bytes, journal.scope)?;
            if target.is_some_and(|previous| next.sequence <= previous.sequence)
                || !journal.store.contains(next)
            {
                return Err(Error::Invalid);
            }
            target = Some(next);
        }
        let acknowledged = store.head().ok_or(Error::Invalid)?;
        if acknowledged.sequence
            != u64::try_from(store.records().len()).map_err(|_| Error::Invalid)?
            || !valid_digest(acknowledged.root)
            || !store.contains(acknowledged)
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            store,
            scope: journal.scope,
            target: target.ok_or(Error::Invalid)?,
            acknowledged,
            fenced: false,
        })
    }

    /// Latest acknowledged keeper prefix, for independent retention.
    pub fn anchor(&self) -> EffectJournalPin {
        self.acknowledged
    }

    /// Latest journal prefix durably recorded by this keeper.
    pub fn target(&self) -> EffectJournalPin {
        self.target
    }

    pub(super) fn retain(&mut self, journal: &Journal, cx: &ReplayCx) -> Result<(), Error> {
        checkpoint(cx)?;
        if self.fenced || journal.fenced {
            return Err(Error::Fenced);
        }
        if self.scope != journal.scope || !journal.store.contains(self.target) {
            return Err(Error::Invalid);
        }
        let next = journal.anchor();
        if next == self.target {
            return Ok(());
        }
        if next.sequence <= self.target.sequence || self.store.records().len() >= MAX_RECORDS {
            return Err(Error::Invalid);
        }
        let bytes = encode_anchor(self.scope, next)?;
        self.store
            .reserve_capacity(1, MAX_RECORD_BYTES)
            .map_err(Error::Storage)?;
        let appended = match self.store.append(Some(self.acknowledged), &bytes) {
            Ok(pin) => pin,
            Err(error) => {
                self.fenced = true;
                return Err(Error::Storage(error));
            }
        };
        if self.acknowledged.sequence.checked_add(1) != Some(appended.sequence)
            || !valid_digest(appended.root)
        {
            self.fenced = true;
            return Err(Error::Invalid);
        }
        self.acknowledged = appended;
        self.target = next;
        Ok(())
    }
}
