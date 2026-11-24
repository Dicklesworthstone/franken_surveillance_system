#![forbid(unsafe_code)]
//! Materialized `agent_sessions_idx` and `active_cases_idx` with O(1) active-lease lookup
//! and deterministic archival pruning of terminal closed sessions.
//!
//! Terminal closed/revoked/expired sessions are pruned out of the hot working set while
//! retaining exact cumulative counts, a sequential SHA-256 archival commitment digest, and
//! complete immutable audit history inside the sealed `.fssa` epoch segment files.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    DigestAlgorithm, Sha256Hasher, TimestampNs,
};

use crate::error::ProjectionError;

/// Canonical digest domain for [`SessionsIndex::state_digest`].
pub const AGENT_SESSIONS_INDEX_DOMAIN: &str = "fss.agent_index.sessions_state.v1";

/// Record kind tag for serialized [`SessionJournalEvent`] frames inside `agent/sessions/`.
pub const SESSION_EVENT_RECORD_KIND: u16 = 0x0101;

/// Lifecycle status of an indexed agent session.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SessionLifecycle {
    /// Session holds an active authority scope and may execute work.
    Active,
    /// Session was handed off and awaits recipient resume.
    HandedOff,
    /// Session completed and closed cleanly (terminal; eligible for hot-set archival).
    Closed,
    /// Session was explicitly revoked by authority witness (terminal).
    Revoked,
    /// Session lease expired without renewal (terminal).
    Expired,
}

impl SessionLifecycle {
    /// Returns `true` for terminal states (`Closed`, `Revoked`, `Expired`).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed | Self::Revoked | Self::Expired)
    }

    pub(super) const fn to_tag(self) -> u8 {
        match self {
            Self::Active => 1,
            Self::HandedOff => 2,
            Self::Closed => 3,
            Self::Revoked => 4,
            Self::Expired => 5,
        }
    }

    pub(super) const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Active),
            2 => Some(Self::HandedOff),
            3 => Some(Self::Closed),
            4 => Some(Self::Revoked),
            5 => Some(Self::Expired),
            _ => None,
        }
    }
}

/// Lifecycle status of an indexed investigation case.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CaseLifecycle {
    /// Investigation case is open and actively tracking competing hypotheses.
    Open,
    /// Case reached a documented resolution (terminal; archived out of hot set).
    Resolved,
    /// Case was explicitly closed (terminal; archived out of hot set).
    Closed,
}

impl CaseLifecycle {
    /// Returns `true` when the case remains open in `active_cases_idx`.
    #[must_use]
    pub const fn is_open(self) -> bool {
        matches!(self, Self::Open)
    }

    pub(super) const fn to_tag(self) -> u8 {
        match self {
            Self::Open => 1,
            Self::Resolved => 2,
            Self::Closed => 3,
        }
    }

    pub(super) const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Open),
            2 => Some(Self::Resolved),
            3 => Some(Self::Closed),
            _ => None,
        }
    }
}

/// Materialized row in `agent_sessions_idx` for one live or handed-off session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedSession {
    /// Stable unique session identifier.
    pub session_id: String,
    /// Owning mission identifier.
    pub mission_id: String,
    /// Owning principal identifier.
    pub principal_id: String,
    /// Current session lifecycle status.
    pub lifecycle: SessionLifecycle,
    /// Lease expiration timestamp on the deployment evidence clock.
    pub lease_expires_at_ns: TimestampNs,
    /// Latest committed workspace revision number.
    pub workspace_revision: u64,
    /// Session open timestamp.
    pub opened_at_ns: TimestampNs,
    /// Last transition timestamp.
    pub updated_at_ns: TimestampNs,
    /// Journal sequence number of the last applied mutation.
    pub last_seq: u64,
}

/// Materialized row in `active_cases_idx` for one open investigation case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedCase {
    /// Stable investigation case identifier.
    pub case_id: String,
    /// Owning session identifier.
    pub session_id: String,
    /// Owning mission identifier.
    pub mission_id: String,
    /// Current case lifecycle state.
    pub lifecycle: CaseLifecycle,
    /// Count of competing hypotheses retained in this case.
    pub hypothesis_count: u32,
    /// Last update timestamp.
    pub updated_at_ns: TimestampNs,
    /// Journal sequence number of the last applied mutation.
    pub last_seq: u64,
}

/// Canonical event persisted into the `agent/sessions/` segmented epoch journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionJournalEvent {
    /// Opens a new session (or restores a non-terminal session record).
    OpenSession(IndexedSession),
    /// Renews an active session lease and/or advances its workspace revision.
    RenewLease {
        /// Target session identifier.
        session_id: String,
        /// Updated lease expiration timestamp.
        lease_expires_at_ns: TimestampNs,
        /// Updated workspace revision number.
        workspace_revision: u64,
        /// Event timestamp.
        updated_at_ns: TimestampNs,
    },
    /// Transitions a session lifecycle state; terminal states are pruned from the hot index.
    TransitionSession {
        /// Target session identifier.
        session_id: String,
        /// New lifecycle state.
        lifecycle: SessionLifecycle,
        /// Transition timestamp.
        updated_at_ns: TimestampNs,
    },
    /// Opens or updates an investigation case in `active_cases_idx`.
    UpsertCase(IndexedCase),
    /// Transitions an investigation case to a terminal state and prunes it from the hot set.
    CloseCase {
        /// Target case identifier.
        case_id: String,
        /// Terminal lifecycle state (`Resolved` or `Closed`).
        lifecycle: CaseLifecycle,
        /// Closure timestamp.
        updated_at_ns: TimestampNs,
    },
}

/// O(1) orient summary of materialized session, lease, and case indexes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionsIndexSummary {
    /// Total sessions ever recorded across all sealed and active epochs.
    pub total_sessions_ever: u64,
    /// Non-terminal sessions currently held in the hot index.
    pub active_sessions: u64,
    /// Active sessions whose lease has not expired at the queried evidence clock.
    pub active_leases: u64,
    /// Terminal closed/revoked/expired sessions pruned from the hot working set.
    pub archived_terminal_sessions: u64,
    /// Open investigation cases currently held in `active_cases_idx`.
    pub active_cases: u64,
    /// Terminal closed/resolved cases pruned from the hot working set.
    pub archived_closed_cases: u64,
    /// Highest applied journal sequence number.
    pub last_seq: u64,
}

/// Materialized `agent_sessions_idx`, `active_cases_idx`, and active lease index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionsIndex {
    active_sessions: BTreeMap<String, IndexedSession>,
    active_cases: BTreeMap<String, IndexedCase>,
    cases_by_session: BTreeMap<String, BTreeSet<String>>,
    total_sessions_ever: u64,
    archived_terminal_sessions: u64,
    archived_closed_cases: u64,
    archived_audit_digest: ContentDigest,
    last_seq: u64,
}

impl Default for SessionsIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionsIndex {
    /// Creates an empty [`SessionsIndex`] at sequence `0`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            active_sessions: BTreeMap::new(),
            active_cases: BTreeMap::new(),
            cases_by_session: BTreeMap::new(),
            total_sessions_ever: 0,
            archived_terminal_sessions: 0,
            archived_closed_cases: 0,
            archived_audit_digest: ContentDigest::sha256(b"fss.agent_index.sessions_archive.v1"),
            last_seq: 0,
        }
    }

    /// Applies one committed [`SessionJournalEvent`] at `seq`, updating hot maps and archival folds.
    pub fn apply_event(&mut self, seq: u64, event: SessionJournalEvent) {
        self.last_seq = seq;
        match event {
            SessionJournalEvent::OpenSession(mut session) => {
                session.last_seq = seq;
                if !self.active_sessions.contains_key(&session.session_id) {
                    self.total_sessions_ever = self.total_sessions_ever.saturating_add(1);
                }
                if session.lifecycle.is_terminal() {
                    self.fold_archived_session(
                        &session.session_id,
                        session.lifecycle,
                        session.updated_at_ns,
                        seq,
                    );
                } else {
                    self.active_sessions
                        .insert(session.session_id.clone(), session);
                }
            }
            SessionJournalEvent::RenewLease {
                session_id,
                lease_expires_at_ns,
                workspace_revision,
                updated_at_ns,
            } => {
                if let Some(session) = self.active_sessions.get_mut(&session_id) {
                    session.lease_expires_at_ns = lease_expires_at_ns;
                    session.workspace_revision = workspace_revision;
                    session.updated_at_ns = updated_at_ns;
                    session.last_seq = seq;
                }
            }
            SessionJournalEvent::TransitionSession {
                session_id,
                lifecycle,
                updated_at_ns,
            } => {
                if lifecycle.is_terminal() {
                    if self.active_sessions.remove(&session_id).is_some() {
                        self.fold_archived_session(&session_id, lifecycle, updated_at_ns, seq);
                    }
                } else if let Some(session) = self.active_sessions.get_mut(&session_id) {
                    session.lifecycle = lifecycle;
                    session.updated_at_ns = updated_at_ns;
                    session.last_seq = seq;
                }
            }
            SessionJournalEvent::UpsertCase(mut case) => {
                case.last_seq = seq;
                if case.lifecycle.is_open() {
                    self.cases_by_session
                        .entry(case.session_id.clone())
                        .or_default()
                        .insert(case.case_id.clone());
                    self.active_cases.insert(case.case_id.clone(), case);
                } else {
                    self.remove_case(&case.case_id, case.lifecycle, case.updated_at_ns, seq);
                }
            }
            SessionJournalEvent::CloseCase {
                case_id,
                lifecycle,
                updated_at_ns,
            } => self.remove_case(&case_id, lifecycle, updated_at_ns, seq),
        }
    }

    /// Looks up a non-terminal session in `O(log active)` over the hot active set.
    #[must_use]
    pub fn get_active_session(&self, session_id: &str) -> Option<&IndexedSession> {
        self.active_sessions.get(session_id)
    }

    /// Returns `true` if `session_id` is `Active` and its lease has not expired at `now`.
    #[must_use]
    pub fn is_lease_active(&self, session_id: &str, now: TimestampNs) -> bool {
        self.active_sessions
            .get(session_id)
            .is_some_and(|s| s.lifecycle == SessionLifecycle::Active && s.lease_expires_at_ns > now)
    }

    /// Looks up an open investigation case by identifier.
    #[must_use]
    pub fn get_active_case(&self, case_id: &str) -> Option<&IndexedCase> {
        self.active_cases.get(case_id)
    }

    /// Lists open investigation cases owned by `session_id`.
    #[must_use]
    pub fn active_cases_for_session(&self, session_id: &str) -> Vec<&IndexedCase> {
        self.cases_by_session
            .get(session_id)
            .map_or_else(Vec::new, |ids| {
                ids.iter()
                    .filter_map(|id| self.active_cases.get(id))
                    .collect()
            })
    }

    /// Returns an `O(active)` summary (constant time relative to archived historical sessions).
    #[must_use]
    pub fn summary(&self, now: TimestampNs) -> SessionsIndexSummary {
        let active_leases = self
            .active_sessions
            .values()
            .filter(|s| s.lifecycle == SessionLifecycle::Active && s.lease_expires_at_ns > now)
            .count() as u64;
        SessionsIndexSummary {
            total_sessions_ever: self.total_sessions_ever,
            active_sessions: self.active_sessions.len() as u64,
            active_leases,
            archived_terminal_sessions: self.archived_terminal_sessions,
            active_cases: self.active_cases.len() as u64,
            archived_closed_cases: self.archived_closed_cases,
            last_seq: self.last_seq,
        }
    }

    /// Returns the total count of sessions ever observed (active + archived).
    #[must_use]
    pub const fn total_sessions_ever(&self) -> u64 {
        self.total_sessions_ever
    }

    /// Returns the count of terminal sessions pruned from the hot working set.
    #[must_use]
    pub const fn archived_terminal_sessions(&self) -> u64 {
        self.archived_terminal_sessions
    }

    /// Serializes this materialized index into canonical checkpoint payload bytes.
    pub fn encode_checkpoint_bytes(&self) -> Result<Vec<u8>, ProjectionError> {
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        Ok(enc.finish_checked()?)
    }

    /// Decodes a verified [`SessionsIndex`] from canonical checkpoint payload bytes.
    pub fn decode_checkpoint_bytes(bytes: &[u8]) -> Result<Self, ProjectionError> {
        let mut dec = CanonicalDecoder::new(bytes);
        if dec.text()? != AGENT_SESSIONS_INDEX_DOMAIN {
            return Err(ProjectionError::CorruptDerivedStore {
                artifact: "sessions_index_checkpoint",
                detail: "invalid sessions checkpoint domain".to_owned(),
            });
        }
        let last_seq = dec.u64()?;
        let total_sessions_ever = dec.u64()?;
        let archived_terminal_sessions = dec.u64()?;
        let archived_closed_cases = dec.u64()?;
        let archived_audit_digest = dec.digest()?;

        let s_len = usize::try_from(dec.u64()?)
            .map_err(|_| ProjectionError::ArithmeticOverflow("active_sessions_len"))?;
        let mut active_sessions = BTreeMap::new();
        for _ in 0..s_len {
            let s = IndexedSession::decode_canonical(&mut dec)?;
            active_sessions.insert(s.session_id.clone(), s);
        }
        let c_len = usize::try_from(dec.u64()?)
            .map_err(|_| ProjectionError::ArithmeticOverflow("active_cases_len"))?;
        let mut active_cases = BTreeMap::new();
        let mut cases_by_session: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for _ in 0..c_len {
            let c = IndexedCase::decode_canonical(&mut dec)?;
            cases_by_session
                .entry(c.session_id.clone())
                .or_default()
                .insert(c.case_id.clone());
            active_cases.insert(c.case_id.clone(), c);
        }
        dec.ensure_finished()?;
        Ok(Self {
            active_sessions,
            active_cases,
            cases_by_session,
            total_sessions_ever,
            archived_terminal_sessions,
            archived_closed_cases,
            archived_audit_digest,
            last_seq,
        })
    }

    /// Computes the deterministic SHA-256 state digest under [`AGENT_SESSIONS_INDEX_DOMAIN`].
    #[must_use]
    pub fn state_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        ContentDigest::sha256(&enc.finish())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(AGENT_SESSIONS_INDEX_DOMAIN);
        enc.u64(self.last_seq);
        enc.u64(self.total_sessions_ever);
        enc.u64(self.archived_terminal_sessions);
        enc.u64(self.archived_closed_cases);
        enc.digest(self.archived_audit_digest);
        enc.u64(self.active_sessions.len() as u64);
        for s in self.active_sessions.values() {
            s.encode_canonical(enc);
        }
        enc.u64(self.active_cases.len() as u64);
        for c in self.active_cases.values() {
            c.encode_canonical(enc);
        }
    }

    fn fold_archived_session(
        &mut self,
        session_id: &str,
        lifecycle: SessionLifecycle,
        updated_at_ns: TimestampNs,
        seq: u64,
    ) {
        self.archived_terminal_sessions = self.archived_terminal_sessions.saturating_add(1);
        let mut h = Sha256Hasher::new();
        h.update(b"session-archive:");
        h.update(&self.archived_audit_digest.bytes());
        h.update(&seq.to_be_bytes());
        h.update(&[lifecycle.to_tag()]);
        h.update(&updated_at_ns.0.to_be_bytes());
        h.update(session_id.as_bytes());
        self.archived_audit_digest =
            ContentDigest::new(DigestAlgorithm::Sha256, h.finalize().unwrap_or_default());
    }

    fn remove_case(
        &mut self,
        case_id: &str,
        lifecycle: CaseLifecycle,
        updated_at_ns: TimestampNs,
        seq: u64,
    ) {
        if let Some(removed) = self.active_cases.remove(case_id) {
            if let Some(set) = self.cases_by_session.get_mut(&removed.session_id) {
                set.remove(case_id);
                if set.is_empty() {
                    self.cases_by_session.remove(&removed.session_id);
                }
            }
            self.archived_closed_cases = self.archived_closed_cases.saturating_add(1);
            let mut h = Sha256Hasher::new();
            h.update(b"case-archive:");
            h.update(&self.archived_audit_digest.bytes());
            h.update(&seq.to_be_bytes());
            h.update(&[lifecycle.to_tag()]);
            h.update(&updated_at_ns.0.to_be_bytes());
            h.update(case_id.as_bytes());
            self.archived_audit_digest =
                ContentDigest::new(DigestAlgorithm::Sha256, h.finalize().unwrap_or_default());
        }
    }
}
