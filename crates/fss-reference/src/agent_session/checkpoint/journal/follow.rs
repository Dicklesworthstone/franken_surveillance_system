#![forbid(unsafe_code)]
//! Session-owned delivery progress in the existing session journal.
//!
//! These records acknowledge presentation, never create evidence or effect history. A delivery
//! is retained before release and advances only on an exact, explicit acknowledgement. Recovery
//! re-executes the bounded state machine against the session authority at each journal position.

use std::collections::BTreeMap;
use std::fmt;

use fss_core::{
    AgentView, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest, PrincipalId,
    SessionId, TimestampNs,
};

use super::{DurableSessionError, DurableSessionLimits, DurableSessionStore, PendingSession};
use crate::agent_follow::replay::ReplayStep;
use crate::agent_follow::{AnchorToken, MAX_FOLLOW_ENTRIES};
use crate::agent_session::ReferenceSessionStore;

/// Additive record kind; older readers refuse it instead of losing subscription progress.
pub const FOLLOW_COMMAND_RECORD_KIND: u16 = 0x464c;
/// Whole-journal retained subscription ceiling, including sessions that later close.
pub const MAX_FOLLOW_SUBSCRIPTIONS: usize = 256;
/// A single session cannot monopolize the retained subscription inventory.
pub const MAX_SESSION_FOLLOW_SUBSCRIPTIONS: usize = 16;
/// One canonical command has a hard ceiling independent of journal capacity.
pub const MAX_FOLLOW_RECORD_BYTES: usize = 64 * 1024;
/// Subscription labels never become filesystem paths.
pub const MAX_SUBSCRIPTION_ID_BYTES: usize = 128;
const MAX_TOKEN_BYTES: usize = 256;
const RECORD_DOMAIN: &str = "fss.reference_follow_session_command.v1";
const REGISTRATION_DOMAIN: &str = "fss.reference_follow_session_registration.v1";
const STATE_DOMAIN: &str = "fss.reference_follow_session_state.v1";
const DELIVERY_DOMAIN: &str = "fss.reference_follow_delivery.v1";

/// Refusals contain no private result or hidden subscription identity.
#[derive(Debug)]
pub enum DurableFollowError {
    /// Session, journal, or durable ownership admission failed.
    Session(Box<DurableSessionError>),
    /// Invalid bounded label, anchor, view, or page size.
    InvalidRequest,
    /// The live authority projection differs from the one that registered this subscription.
    StaleScope,
    /// The requested identity, revision, page, or acknowledgement does not match retained state.
    Conflict,
    /// Retained subscriptions, revision counters, or command bytes exceeded a ceiling.
    CapacityExceeded,
}

impl fmt::Display for DurableFollowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Session(_) => "durable follow session or journal refused",
            Self::InvalidRequest => "invalid bounded follow subscription request",
            Self::StaleScope => "follow subscription authority projection changed",
            Self::Conflict => {
                "follow subscription or acknowledgement does not match retained state"
            }
            Self::CapacityExceeded => "durable follow capacity exhausted",
        })
    }
}

impl std::error::Error for DurableFollowError {}

impl From<DurableSessionError> for DurableFollowError {
    fn from(value: DurableSessionError) -> Self {
        Self::Session(Box::new(value))
    }
}

/// Immutable subscription request. The original anchor remains the retry identity after ACKs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FollowRegistration {
    /// Owning authenticated session.
    pub session_id: SessionId,
    /// Bounded caller-selected label, scoped to this session.
    pub subscription_id: String,
    /// Exact original deployment position, including the effect-journal prefix.
    pub since: String,
    /// Registered view, frozen for this subscription.
    pub view: AgentView,
    /// Frozen maximum items per page.
    pub max_entries: u32,
    /// Exact non-follow agent history and publication scope verified by the deployment owner.
    pub semantic_history: ContentDigest,
}

impl FollowRegistration {
    /// Validates syntax and hard bounds without I/O or session mutation.
    pub fn validate(&self) -> Result<(), DurableFollowError> {
        if self.subscription_id.is_empty()
            || self.subscription_id.len() > MAX_SUBSCRIPTION_ID_BYTES
            || !self
                .subscription_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
            || AnchorToken::parse(&self.since).is_none()
            || !matches!(self.view, AgentView::Pulse | AgentView::Brief)
            || self.max_entries == 0
            || self.max_entries > MAX_FOLLOW_ENTRIES
        {
            return Err(DurableFollowError::InvalidRequest);
        }
        Ok(())
    }

    fn encode(&self, e: &mut CanonicalEncoder) {
        e.text(self.session_id.as_str());
        e.text(&self.subscription_id);
        e.text(&self.since);
        e.text(self.view.id());
        e.u32(self.max_entries);
        e.digest(self.semantic_history);
    }
}

/// A single unacknowledged page. Construction is restricted to a checked native replay step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingFollowDelivery {
    since: String,
    result: String,
    horizon: String,
    input_continuation: Option<String>,
    next_continuation: Option<String>,
    page_start: u64,
    page_len: u64,
    total_items: u64,
    page_digest: ContentDigest,
    result_fingerprint: ContentDigest,
    receipt: ContentDigest,
}

impl PendingFollowDelivery {
    /// Exact delivery receipt the client must acknowledge.
    #[must_use]
    pub const fn receipt(&self) -> ContentDigest {
        self.receipt
    }
    /// Exact native page/publication fingerprint checked again before every redelivery.
    #[must_use]
    pub const fn page_digest(&self) -> ContentDigest {
        self.page_digest
    }
    /// First position of this adjacent transition, unchanged until all its pages are ACKed.
    #[must_use]
    pub fn since(&self) -> &str {
        &self.since
    }
    /// Exact adjacent endpoint; never a guessed cross-journal interleaving.
    #[must_use]
    pub fn result_anchor(&self) -> &str {
        &self.result
    }
    /// Frozen replay horizon, independent of subsequent appends.
    #[must_use]
    pub fn horizon(&self) -> &str {
        &self.horizon
    }
    /// Input page cursor that reproduces this delivery.
    #[must_use]
    pub fn input_continuation(&self) -> Option<&str> {
        self.input_continuation.as_deref()
    }

    pub(crate) fn from_step(
        state: &FollowSubscription,
        step: &ReplayStep,
    ) -> Result<Self, DurableFollowError> {
        let result_fingerprint = step
            .follow
            .result
            .capsule()
            .decision_fingerprint()
            .map_err(|_| DurableFollowError::InvalidRequest)?;
        let mut pending = Self {
            since: step.since.as_str().to_owned(),
            result: step.result_anchor.as_str().to_owned(),
            horizon: step.horizon.as_str().to_owned(),
            input_continuation: state.next_continuation.clone(),
            next_continuation: step
                .follow
                .page
                .next_cursor
                .as_ref()
                .map(|c| c.cursor_id.clone()),
            page_start: step.follow.page_start(),
            page_len: step.follow.page.entries.len() as u64,
            total_items: step.follow.items.len() as u64,
            page_digest: step.page_digest(),
            result_fingerprint,
            receipt: ContentDigest::sha256(&[]),
        };
        pending.receipt = pending.computed_receipt(state);
        pending.validate_for(state)?;
        Ok(pending)
    }

    fn encode_body(&self, e: &mut CanonicalEncoder) {
        e.text(&self.since);
        e.text(&self.result);
        e.text(&self.horizon);
        optional_text(e, self.input_continuation.as_deref());
        optional_text(e, self.next_continuation.as_deref());
        e.u64(self.page_start);
        e.u64(self.page_len);
        e.u64(self.total_items);
        e.digest(self.page_digest);
        e.digest(self.result_fingerprint);
    }

    fn computed_receipt(&self, state: &FollowSubscription) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(DELIVERY_DOMAIN);
        e.digest(state.digest());
        self.encode_body(&mut e);
        ContentDigest::sha256(&e.finish())
    }

    fn validate_for(&self, state: &FollowSubscription) -> Result<(), DurableFollowError> {
        let parse = |s: &str| AnchorToken::parse(s).ok_or(DurableFollowError::InvalidRequest);
        let from = parse(&self.since)?;
        let to = parse(&self.result)?;
        let horizon = parse(&self.horizon)?;
        let a = from.position();
        let b = to.position();
        let h = horizon.position();
        let same_site = |left: &AnchorToken, right: &AnchorToken| {
            left.as_str().split(':').nth(1) == right.as_str().split(':').nth(1)
        };
        let adjacent_ledger = a.effect_records == b.effect_records
            && a.commit_sequence.checked_add(1) == Some(b.commit_sequence);
        let adjacent_effect = a.commit_sequence == b.commit_sequence
            && match (a.effect_records, b.effect_records) {
                (None, Some(0)) => true,
                (Some(a), Some(b)) => a.checked_add(1) == Some(b),
                _ => false,
            };
        let caught_up = from == to && to == horizon;
        let end = self
            .page_start
            .checked_add(self.page_len)
            .ok_or(DurableFollowError::CapacityExceeded)?;
        if state.pending.is_some()
            || self.since != state.acknowledged_anchor
            || self.input_continuation != state.next_continuation
            || self.page_start != state.next_offset
            || self.page_len > u64::from(state.registration.max_entries)
            || end > self.total_items
            || (self.page_len == 0 && self.total_items != 0)
            || (end < self.total_items) != self.next_continuation.is_some()
            || self.next_continuation == self.input_continuation && self.next_continuation.is_some()
            || state.horizon.as_ref().is_some_and(|h| h != &self.horizon)
            || !same_site(&from, &to)
            || !same_site(&from, &horizon)
            || h.commit_sequence < b.commit_sequence
            || h.effect_records < b.effect_records
            || (a.commit_sequence != h.commit_sequence && a.effect_records != h.effect_records)
            || !(adjacent_ledger || adjacent_effect || caught_up)
            || self.receipt != self.computed_receipt(state)
        {
            return Err(DurableFollowError::Conflict);
        }
        for cursor in [&self.input_continuation, &self.next_continuation]
            .into_iter()
            .flatten()
        {
            if cursor.is_empty() || cursor.len() > MAX_TOKEN_BYTES {
                return Err(DurableFollowError::InvalidRequest);
            }
        }
        Ok(())
    }
}

/// Historical continuity state; possession of this object never grants live access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FollowSubscription {
    registration: FollowRegistration,
    authority_digest: ContentDigest,
    acknowledged_anchor: String,
    acknowledged_fingerprint: Option<ContentDigest>,
    horizon: Option<String>,
    next_continuation: Option<String>,
    next_offset: u64,
    revision: u64,
    last_acknowledged: Option<ContentDigest>,
    pending: Option<PendingFollowDelivery>,
}

impl FollowSubscription {
    /// Immutable registration, including original anchor and view/page bounds.
    #[must_use]
    pub const fn registration(&self) -> &FollowRegistration {
        &self.registration
    }
    /// Last completely acknowledged adjacent endpoint.
    #[must_use]
    pub fn acknowledged_anchor(&self) -> &str {
        &self.acknowledged_anchor
    }
    /// Frozen remaining window, absent after its final page has been acknowledged.
    #[must_use]
    pub fn horizon(&self) -> Option<&str> {
        self.horizon.as_deref()
    }
    /// Exact next page within an incompletely acknowledged adjacent transition.
    #[must_use]
    pub fn next_continuation(&self) -> Option<&str> {
        self.next_continuation.as_deref()
    }
    /// A page retained before response release and not yet acknowledged.
    #[must_use]
    pub const fn pending(&self) -> Option<&PendingFollowDelivery> {
        self.pending.as_ref()
    }
    /// Last successful ACK, retained for lost-response retries.
    #[must_use]
    pub const fn last_acknowledged(&self) -> Option<ContentDigest> {
        self.last_acknowledged
    }
    /// Last completely acknowledged situation fingerprint, never inferred from rendering.
    #[must_use]
    pub const fn acknowledged_fingerprint(&self) -> Option<ContentDigest> {
        self.acknowledged_fingerprint
    }
    /// Exact CAS revision of the whole continuity state.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(STATE_DOMAIN);
        e.text("subscription");
        self.encode(&mut e);
        ContentDigest::sha256(&e.finish())
    }

    fn encode(&self, e: &mut CanonicalEncoder) {
        self.registration.encode(e);
        e.digest(self.authority_digest);
        e.text(&self.acknowledged_anchor);
        optional_digest(e, self.acknowledged_fingerprint);
        optional_text(e, self.horizon.as_deref());
        optional_text(e, self.next_continuation.as_deref());
        e.u64(self.next_offset);
        e.u64(self.revision);
        optional_digest(e, self.last_acknowledged);
        e.bool(self.pending.is_some());
        if let Some(pending) = &self.pending {
            pending.encode_body(e);
            e.digest(pending.receipt);
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct FollowState {
    subscriptions: BTreeMap<(SessionId, String), FollowSubscription>,
}

impl FollowState {
    pub(super) fn retained(&self) -> Vec<FollowSubscription> {
        self.subscriptions.values().cloned().collect()
    }

    fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(STATE_DOMAIN);
        e.text("store");
        e.u64(self.subscriptions.len() as u64);
        for subscription in self.subscriptions.values() {
            e.digest(subscription.digest());
        }
        ContentDigest::sha256(&e.finish())
    }
}

#[derive(Clone, Debug)]
enum Command {
    Register(FollowRegistration),
    Deliver {
        subscription: String,
        expected: ContentDigest,
        pending: PendingFollowDelivery,
    },
    Acknowledge {
        subscription: String,
        receipt: ContentDigest,
    },
}

impl Command {
    fn subscription(&self) -> &str {
        match self {
            Self::Register(r) => &r.subscription_id,
            Self::Deliver { subscription, .. } | Self::Acknowledge { subscription, .. } => {
                subscription
            }
        }
    }
}

fn authority_digest(
    memory: &mut ReferenceSessionStore,
    principal: &PrincipalId,
    session_id: &SessionId,
    now: TimestampNs,
) -> Result<ContentDigest, DurableFollowError> {
    let entry = memory
        .live_entry(principal, session_id, now)
        .map_err(DurableSessionError::Session)?;
    if ![
        "CAP-AGENT-SESSION-READ-001",
        "CAP-AGENT-SESSION-WRITE-001",
        "CAP-AGENT-SITUATION-READ-001",
    ]
    .iter()
    .all(|grant| entry.session.capabilities.contains(*grant))
        || !entry.session.privacy_scope.contains("private:property")
    {
        return Err(DurableFollowError::StaleScope);
    }
    let mut e = CanonicalEncoder::new();
    e.text(REGISTRATION_DOMAIN);
    e.text("authority");
    e.text(principal.as_str());
    e.text(session_id.as_str());
    e.text(entry.session.mission_id.as_str());
    entry.basis.encode_canonical(&mut e);
    e.i128(entry.session.created_at_ns);
    e.i128(entry.session.expires_at_ns);
    e.u64(entry.session.token_budget);
    for grants in [&entry.session.capabilities, &entry.session.privacy_scope] {
        e.u64(grants.len() as u64);
        for grant in grants {
            e.text(grant);
        }
    }
    Ok(ContentDigest::sha256(&e.finish()))
}

fn apply(
    memory: &mut ReferenceSessionStore,
    state: &mut FollowState,
    principal: &PrincipalId,
    session_id: &SessionId,
    command: &Command,
    now: TimestampNs,
) -> Result<FollowSubscription, DurableFollowError> {
    let authority = authority_digest(memory, principal, session_id, now)?;
    let key = (session_id.clone(), command.subscription().to_owned());
    if let Command::Register(registration) = command {
        registration.validate()?;
        if registration.session_id != *session_id {
            return Err(DurableFollowError::InvalidRequest);
        }
        if let Some(existing) = state.subscriptions.get(&key) {
            if existing.authority_digest != authority
                || existing.registration.semantic_history != registration.semantic_history
            {
                return Err(DurableFollowError::StaleScope);
            }
            return if existing.registration == *registration {
                Ok(existing.clone())
            } else {
                Err(DurableFollowError::Conflict)
            };
        }
        if state.subscriptions.len() >= MAX_FOLLOW_SUBSCRIPTIONS
            || state
                .subscriptions
                .keys()
                .filter(|(session, _)| session == session_id)
                .count()
                >= MAX_SESSION_FOLLOW_SUBSCRIPTIONS
        {
            return Err(DurableFollowError::CapacityExceeded);
        }
        let result = FollowSubscription {
            registration: registration.clone(),
            authority_digest: authority,
            acknowledged_anchor: registration.since.clone(),
            acknowledged_fingerprint: None,
            horizon: None,
            next_continuation: None,
            next_offset: 0,
            revision: 0,
            last_acknowledged: None,
            pending: None,
        };
        state.subscriptions.insert(key, result.clone());
        return Ok(result);
    }
    let current = state
        .subscriptions
        .get(&key)
        .ok_or(DurableFollowError::Conflict)?;
    if current.authority_digest != authority {
        return Err(DurableFollowError::StaleScope);
    }
    let mut next = current.clone();
    match command {
        Command::Register(_) => return Err(DurableFollowError::InvalidRequest),
        Command::Deliver {
            expected, pending, ..
        } => {
            if current.digest() != *expected {
                return Err(DurableFollowError::Conflict);
            }
            pending.validate_for(current)?;
            next.horizon = Some(pending.horizon.clone());
            next.pending = Some(pending.clone());
        }
        Command::Acknowledge { receipt, .. } => {
            if current.last_acknowledged == Some(*receipt) {
                return Ok(current.clone());
            }
            let pending = current
                .pending
                .as_ref()
                .filter(|p| p.receipt == *receipt)
                .ok_or(DurableFollowError::Conflict)?;
            next.last_acknowledged = Some(*receipt);
            next.next_continuation = pending.next_continuation.clone();
            next.next_offset = if next.next_continuation.is_some() {
                pending
                    .page_start
                    .checked_add(pending.page_len)
                    .ok_or(DurableFollowError::CapacityExceeded)?
            } else {
                0
            };
            if next.next_continuation.is_none() {
                next.acknowledged_anchor = pending.result.clone();
                next.acknowledged_fingerprint = Some(pending.result_fingerprint);
                if pending.result == pending.horizon {
                    next.horizon = None;
                }
            }
            next.pending = None;
        }
    }
    next.revision = current
        .revision
        .checked_add(1)
        .ok_or(DurableFollowError::CapacityExceeded)?;
    state.subscriptions.insert(key, next.clone());
    Ok(next)
}

impl DurableSessionStore {
    /// Last retained agent-semantic commands, excluding follow progress and ordinary session
    /// checkpoints. The first root preserves the original empty-facet profile's identity; the
    /// second also includes every supervision command for a populated, pinned baseline.
    /// Both detect a case/claim/workspace that later returns to its old visible state.
    pub(crate) fn follow_semantic_journal_roots(
        &mut self,
    ) -> Result<(ContentDigest, ContentDigest), DurableSessionError> {
        self.preflight()?;
        let report = super::read_report(self.path(), self.limits)?;
        if report.last_root() != self.committed_root()
            || report.committed_len() != self.journal.committed_len()
            || report.incomplete_tail().is_some()
        {
            self.fenced = true;
            return Err(DurableSessionError::RootMismatch);
        }
        let semantic = report
            .records()
            .iter()
            .rev()
            .find(|record| {
                record.kind() != FOLLOW_COMMAND_RECORD_KIND
                    && record.kind() != super::SESSION_CHECKPOINT_RECORD_KIND
            })
            .map_or_else(
                || ContentDigest::sha256(&[]),
                fss_ledger::JournalRecord::root,
            );
        let legacy = report
            .records()
            .iter()
            .rev()
            .find(|record| {
                record.kind() != FOLLOW_COMMAND_RECORD_KIND
                    && record.kind() != super::SESSION_CHECKPOINT_RECORD_KIND
                    && record.kind() != super::supervision::SUPERVISION_COMMAND_RECORD_KIND
            })
            .map_or_else(
                || ContentDigest::sha256(&[]),
                fss_ledger::JournalRecord::root,
            );
        Ok((legacy, semantic))
    }

    /// Authenticate an existing subscription without registering or acknowledging anything.
    /// The adapter uses this to distinguish a retry from a new pinned baseline before writes.
    pub(crate) fn follow_subscription(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        subscription: &str,
        now: TimestampNs,
    ) -> Result<Option<FollowSubscription>, DurableFollowError> {
        self.session(principal, session, now)?;
        let state = self.read_follow_state()?;
        let authority = authority_digest(&mut self.memory.clone(), principal, session, now)?;
        let retained = state
            .subscriptions
            .get(&(session.clone(), subscription.to_owned()));
        if retained.is_some_and(|state| state.authority_digest != authority) {
            return Err(DurableFollowError::StaleScope);
        }
        Ok(retained.cloned())
    }

    /// The already authenticated session's exact interpretation basis, for native page sealing.
    pub(crate) fn follow_contract_basis(
        &self,
        session: &SessionId,
    ) -> Option<&fss_core::ContractBasis> {
        self.memory.sessions.get(session).map(|entry| &entry.basis)
    }

    /// Registers exact continuity once; retries retain pending delivery, ACKs, lease, and grants.
    pub fn register_follow(
        &mut self,
        principal: &PrincipalId,
        registration: FollowRegistration,
        now: TimestampNs,
    ) -> Result<FollowSubscription, DurableFollowError> {
        registration.validate()?;
        let session = registration.session_id.clone();
        self.follow_command(principal, &session, Command::Register(registration), now)
    }

    /// Acknowledges only the one pending page, or the exact most recent ACK retry.
    pub fn acknowledge_follow(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        subscription: &str,
        receipt: ContentDigest,
        now: TimestampNs,
    ) -> Result<FollowSubscription, DurableFollowError> {
        self.follow_command(
            principal,
            session,
            Command::Acknowledge {
                subscription: subscription.to_owned(),
                receipt,
            },
            now,
        )
    }

    pub(crate) fn publish_follow_delivery(
        &mut self,
        principal: &PrincipalId,
        state: &FollowSubscription,
        pending: PendingFollowDelivery,
        now: TimestampNs,
    ) -> Result<FollowSubscription, DurableFollowError> {
        self.follow_command(
            principal,
            &state.registration.session_id,
            Command::Deliver {
                subscription: state.registration.subscription_id.clone(),
                expected: state.digest(),
                pending,
            },
            now,
        )
    }

    fn follow_command(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        command: Command,
        now: TimestampNs,
    ) -> Result<FollowSubscription, DurableFollowError> {
        if command.subscription().is_empty()
            || command.subscription().len() > MAX_SUBSCRIPTION_ID_BYTES
        {
            return Err(DurableFollowError::InvalidRequest);
        }
        // Error-side clock and expiry observations use the existing committed checkpoint path.
        self.session(principal, session, now)?;
        let mut state = self.read_follow_state()?;
        let before_state = state.digest();
        let mut memory = self.memory.clone();
        let result = apply(&mut memory, &mut state, principal, session, &command, now)?;
        let after_state = state.digest();
        if before_state == after_state {
            return Ok(result);
        }
        let checkpoint = memory
            .checkpoint(self.limits.max_checkpoint_bytes)
            .map_err(DurableSessionError::from)?;
        if checkpoint.digest() != self.checkpoint_digest {
            return Err(DurableSessionError::InvalidHistory.into());
        }
        let payload = encode_record(&Record {
            principal: principal.clone(),
            session: session.clone(),
            now,
            session_digest: self.checkpoint_digest,
            before_state,
            after_state,
            command,
        })?;
        self.commit_candidate(PendingSession {
            memory,
            checkpoint,
            coordination: None,
            record: Some((FOLLOW_COMMAND_RECORD_KIND, payload)),
        })?;
        Ok(result)
    }

    fn read_follow_state(&mut self) -> Result<FollowState, DurableFollowError> {
        self.preflight()?;
        let report = super::read_report(self.path(), self.limits)?;
        if report.last_root() != self.committed_root()
            || report.committed_len() != self.journal.committed_len()
            || report.incomplete_tail().is_some()
        {
            self.fenced = true;
            return Err(DurableSessionError::RootMismatch.into());
        }
        let ceilings = self.coordination.as_ref().map(|state| state.limits);
        let restored = super::replay_all(&report, self.limits, ceilings)?;
        if restored
            .memory
            .checkpoint(self.limits.max_checkpoint_bytes)
            .map_err(DurableSessionError::from)?
            .digest()
            != self.checkpoint_digest
        {
            self.fenced = true;
            return Err(DurableSessionError::InvalidHistory.into());
        }
        Ok(restored.follows)
    }
}

struct Record {
    principal: PrincipalId,
    session: SessionId,
    now: TimestampNs,
    session_digest: ContentDigest,
    before_state: ContentDigest,
    after_state: ContentDigest,
    command: Command,
}

fn optional_text(e: &mut CanonicalEncoder, value: Option<&str>) {
    e.bool(value.is_some());
    if let Some(value) = value {
        e.text(value);
    }
}

fn optional_digest(e: &mut CanonicalEncoder, value: Option<ContentDigest>) {
    e.bool(value.is_some());
    if let Some(value) = value {
        e.digest(value);
    }
}

fn read_text(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<String, DurableSessionError> {
    let value = d.text()?;
    if value.len() > maximum {
        return Err(DurableSessionError::CapacityExceeded);
    }
    Ok(value.to_owned())
}

fn read_optional_text(d: &mut CanonicalDecoder<'_>) -> Result<Option<String>, DurableSessionError> {
    if d.bool()? {
        Ok(Some(read_text(d, MAX_TOKEN_BYTES)?))
    } else {
        Ok(None)
    }
}

fn encode_record(record: &Record) -> Result<Vec<u8>, DurableSessionError> {
    let mut e = CanonicalEncoder::new();
    e.text(RECORD_DOMAIN);
    e.text(record.principal.as_str());
    e.text(record.session.as_str());
    e.i128(record.now.0);
    e.digest(record.session_digest);
    e.digest(record.before_state);
    e.digest(record.after_state);
    match &record.command {
        Command::Register(registration) => {
            e.tag(0);
            registration.encode(&mut e);
        }
        Command::Deliver {
            subscription,
            expected,
            pending,
        } => {
            e.tag(1);
            e.text(subscription);
            e.digest(*expected);
            pending.encode_body(&mut e);
            e.digest(pending.receipt);
        }
        Command::Acknowledge {
            subscription,
            receipt,
        } => {
            e.tag(2);
            e.text(subscription);
            e.digest(*receipt);
        }
    }
    let bytes = e.finish_checked()?;
    if bytes.len() > MAX_FOLLOW_RECORD_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    Ok(bytes)
}

fn decode_record(bytes: &[u8]) -> Result<Record, DurableSessionError> {
    if bytes.len() > MAX_FOLLOW_RECORD_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != RECORD_DOMAIN {
        return Err(DurableSessionError::InvalidHistory);
    }
    let principal = PrincipalId::parse(&read_text(&mut d, 512)?)?;
    let session = SessionId::parse(&read_text(&mut d, 512)?)?;
    let now = TimestampNs(d.i128()?);
    let session_digest = d.digest()?;
    let before_state = d.digest()?;
    let after_state = d.digest()?;
    let command = match d.tag()? {
        0 => Command::Register(FollowRegistration {
            session_id: SessionId::parse(&read_text(&mut d, 512)?)?,
            subscription_id: read_text(&mut d, MAX_SUBSCRIPTION_ID_BYTES)?,
            since: read_text(&mut d, MAX_TOKEN_BYTES)?,
            view: AgentView::from_id(&read_text(&mut d, 32)?)?,
            max_entries: d.u32()?,
            semantic_history: d.digest()?,
        }),
        1 => Command::Deliver {
            subscription: read_text(&mut d, MAX_SUBSCRIPTION_ID_BYTES)?,
            expected: d.digest()?,
            pending: PendingFollowDelivery {
                since: read_text(&mut d, MAX_TOKEN_BYTES)?,
                result: read_text(&mut d, MAX_TOKEN_BYTES)?,
                horizon: read_text(&mut d, MAX_TOKEN_BYTES)?,
                input_continuation: read_optional_text(&mut d)?,
                next_continuation: read_optional_text(&mut d)?,
                page_start: d.u64()?,
                page_len: d.u64()?,
                total_items: d.u64()?,
                page_digest: d.digest()?,
                result_fingerprint: d.digest()?,
                receipt: d.digest()?,
            },
        },
        2 => Command::Acknowledge {
            subscription: read_text(&mut d, MAX_SUBSCRIPTION_ID_BYTES)?,
            receipt: d.digest()?,
        },
        _ => return Err(DurableSessionError::InvalidHistory),
    };
    d.ensure_finished()?;
    let record = Record {
        principal,
        session,
        now,
        session_digest,
        before_state,
        after_state,
        command,
    };
    if encode_record(&record)? != bytes {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok(record)
}

pub(super) fn replay_command(
    bytes: &[u8],
    memory: &mut ReferenceSessionStore,
    state: &mut FollowState,
    limits: DurableSessionLimits,
) -> Result<(), DurableSessionError> {
    let record = decode_record(bytes)?;
    if memory.checkpoint(limits.max_checkpoint_bytes)?.digest() != record.session_digest
        || state.digest() != record.before_state
    {
        return Err(DurableSessionError::InvalidHistory);
    }
    apply(
        memory,
        state,
        &record.principal,
        &record.session,
        &record.command,
        record.now,
    )
    .map_err(|_| DurableSessionError::InvalidHistory)?;
    if memory.checkpoint(limits.max_checkpoint_bytes)?.digest() != record.session_digest
        || state.digest() != record.after_state
        || record.before_state == record.after_state
    {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
