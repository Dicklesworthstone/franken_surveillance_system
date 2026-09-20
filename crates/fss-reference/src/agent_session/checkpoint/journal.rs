#![forbid(unsafe_code)]
//! Synchronous, sole-writer session persistence over the existing crash-classifying journal.
//!
//! This is a reference adapter, not a cross-process lock or an authentication service. Its path
//! and parent directory must be protected and exclusively owned. Recovery requires an independently
//! trusted exact journal root; missing files and divergent tips never silently start a new store.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::path::Path;

use fss_core::{
    AgentSession, AgentSessionParams, ContentDigest, ContractBasis, HydrationRequest,
    HydrationResponse, PrincipalId, SessionId, TimestampNs,
};
use fss_ledger::{
    AppendReconciliation, HostJournalReadIo, IncompleteTailPolicy, Journal, JournalError,
    JournalReadIo, RecoveryReport, recover_bytes,
};

/// Work claims sharing this journal's exact session authority and durable root.
pub mod coordination;

/// Joint durable disclosure accounting and hydration replay protection.
pub mod disclosure;

use coordination::CoordinationState;
use crate::agent_session::work_claims::{WorkClaimError, WorkClaimLimits};

use super::{MAX_SESSION_CHECKPOINT_BYTES, SessionCheckpoint, SessionCheckpointError};
use crate::ReferenceHydrationCatalog;
use crate::agent_session::{
    ReferenceSessionError, ReferenceSessionLimits, ReferenceSessionStore, ResolvedSessionHandle,
    SessionAlias, SessionBindingRequest, SessionRefresh,
};

/// Dedicated record kind in a session-only reference journal.
pub const SESSION_CHECKPOINT_RECORD_KIND: u16 = 0x5353;
/// Hard ceiling for retained journal bytes, including record framing.
pub const MAX_SESSION_JOURNAL_BYTES: usize = 64 * 1024 * 1024;
// The version-one Journal frame has an 88-byte header and a 40-byte commit trailer.
const RECORD_OVERHEAD_BYTES: usize = 128;

/// Explicit admission ceilings. Reaching a ceiling never discards tombstones or older records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableSessionLimits {
    /// Runtime ceilings on recovered session state.
    pub sessions: ReferenceSessionLimits,
    /// Maximum bytes in one checkpoint, capped by the checkpoint format.
    pub max_checkpoint_bytes: usize,
    /// Maximum journal bytes, capped by `MAX_SESSION_JOURNAL_BYTES`.
    pub max_journal_bytes: usize,
    /// Maximum committed records, including the initial empty checkpoint.
    pub max_records: usize,
}

impl Default for DurableSessionLimits {
    fn default() -> Self {
        Self {
            sessions: ReferenceSessionLimits::default(),
            max_checkpoint_bytes: MAX_SESSION_CHECKPOINT_BYTES,
            max_journal_bytes: MAX_SESSION_JOURNAL_BYTES,
            max_records: 4_096,
        }
    }
}

/// Errors never expose session, principal, or alias targets.
#[derive(Debug)]
pub enum DurableSessionError {
    /// The session protocol refused an operation; any clock/tombstone change was committed.
    Session(ReferenceSessionError),
    /// Coordination refused; its session clock/tombstone changes were committed before return.
    WorkClaim(WorkClaimError),
    /// A private coordination record could not be encoded or decoded canonically.
    CoordinationEncoding(fss_core::ContractError),
    /// Checkpoint encoding or recovery failed.
    Checkpoint(SessionCheckpointError),
    /// Journal corruption, external mutation, or append uncertainty.
    Journal(JournalError),
    /// Filesystem admission or synchronization failed.
    Io(std::io::Error),
    /// The path is not a regular, non-symlink file.
    InvalidLayout,
    /// Journal bytes or record count exceeded the configured ceiling.
    CapacityExceeded,
    /// The complete history does not match the independently pinned root.
    RootMismatch,
    /// Empty journals, foreign record kinds, or incompatible stored limits were found.
    InvalidHistory,
    /// The handle is fenced; no session response may be published until recovery.
    ReconciliationRequired,
}

impl fmt::Display for DurableSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Session(_) => "durable session request refused",
            Self::WorkClaim(_) => "durable work claim request refused",
            Self::CoordinationEncoding(_) => "invalid durable coordination encoding",
            Self::Checkpoint(_) => "durable session checkpoint refused",
            Self::Journal(_) => "durable session journal failed",
            Self::Io(_) => "durable session I/O failed",
            Self::InvalidLayout => "invalid durable session layout",
            Self::CapacityExceeded => "durable session capacity exceeded",
            Self::RootMismatch => "durable session root mismatch",
            Self::InvalidHistory => "invalid durable session history",
            Self::ReconciliationRequired => "durable session reconciliation required",
        })
    }
}

impl std::error::Error for DurableSessionError {}

impl From<fss_core::ContractError> for DurableSessionError {
    fn from(error: fss_core::ContractError) -> Self { Self::CoordinationEncoding(error) }
}

impl From<SessionCheckpointError> for DurableSessionError {
    fn from(error: SessionCheckpointError) -> Self { Self::Checkpoint(error) }
}
impl From<JournalError> for DurableSessionError {
    fn from(error: JournalError) -> Self { Self::Journal(error) }
}
impl From<std::io::Error> for DurableSessionError {
    fn from(error: std::io::Error) -> Self { Self::Io(error) }
}

/// Non-mutating verified history metadata; it is not permission to trust a new root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionJournalInspection {
    /// Exact root of the verified committed prefix.
    pub root: ContentDigest,
    /// Exact checkpoint identity at that prefix's tip.
    pub checkpoint_digest: ContentDigest,
    /// Number of committed records.
    pub records: usize,
    /// Verified committed byte length.
    pub committed_bytes: u64,
    /// A torn final append requires explicit recovery, not an implicit reset.
    pub incomplete_tail: Option<u64>,
}

/// Classification of an append for which no successful response was delivered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionAppendRecovery {
    /// The pending checkpoint is durable and has been installed exactly once.
    Committed,
    /// The pending checkpoint did not commit; prior state remains current.
    NotCommitted,
}

#[derive(Debug)]
struct PendingSession {
    memory: ReferenceSessionStore,
    checkpoint: SessionCheckpoint,
    // None preserves the current coordinator; there is no disable/reset operation.
    coordination: Option<CoordinationState>,
    record: Option<(u16, Vec<u8>)>,
}

impl PendingSession {
    fn kind(&self) -> u16 {
        self.record.as_ref().map_or(SESSION_CHECKPOINT_RECORD_KIND, |(kind, _)| *kind)
    }

    fn payload(&self) -> &[u8] {
        self.record.as_ref().map_or_else(|| self.checkpoint.as_bytes(), |(_, bytes)| bytes.as_slice())
    }
}

/// Session lifecycle with publication after durable commit, including error-side mutations.
///
/// No mutable access to the underlying store is exposed. An ambiguous append fences all session
/// operations, preventing an uncommitted close, refresh, alias, or charge from being acknowledged.
#[derive(Debug)]
pub struct DurableSessionStore {
    journal: Journal,
    memory: ReferenceSessionStore,
    checkpoint_digest: ContentDigest,
    limits: DurableSessionLimits,
    records: usize,
    fenced: bool,
    pending: Option<PendingSession>,
    coordination: Option<CoordinationState>,
}

impl DurableSessionStore {
    /// Creates a new journal only; an existing path is never overwritten or adopted.
    ///
    /// Initial state and its directory entry are synchronized before success. Platforms unable
    /// to synchronize the containing directory return an I/O error rather than claiming durability.
    /// A failed creation may leave a file requiring explicit inspection; it is never deleted here.
    pub fn create(path: impl AsRef<Path>, limits: DurableSessionLimits) -> Result<Self, DurableSessionError> {
        let path = path.as_ref();
        let memory = ReferenceSessionStore::with_limits(limits.sessions);
        let checkpoint = memory.checkpoint(limits.max_checkpoint_bytes)?;
        check_capacity(0, 0, checkpoint.as_bytes().len(), limits)?;
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.sync_all()?;
        drop(file);
        let mut journal = Journal::open(path, IncompleteTailPolicy::Reject)?;
        journal.append(SESSION_CHECKPOINT_RECORD_KIND, checkpoint.as_bytes())?;
        let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()?;
        Ok(Self {
            journal, memory, checkpoint_digest: checkpoint.digest(), limits,
            records: 1, fenced: false, pending: None, coordination: None,
        })
    }

    /// Opens existing, complete, exact history. Never creates missing files or repairs tails.
    pub fn open_existing(
        path: impl AsRef<Path>,
        expected_root: ContentDigest,
        limits: DurableSessionLimits,
    ) -> Result<Self, DurableSessionError> {
        Self::open_with_coordination_ceiling(path.as_ref(), expected_root, limits, None)
    }

    fn open_with_coordination_ceiling(
        path: &Path,
        expected_root: ContentDigest,
        limits: DurableSessionLimits,
        claim_ceilings: Option<WorkClaimLimits>,
    ) -> Result<Self, DurableSessionError> {
        let report = read_report(path, limits)?;
        if report.last_root() != expected_root {
            return Err(DurableSessionError::RootMismatch);
        }
        if let Some(offset) = report.incomplete_tail() {
            return Err(JournalError::IncompleteTail { offset }.into());
        }
        let (memory, coordination) = replay(&report, limits, claim_ceilings)?;
        let checkpoint_digest = memory.checkpoint(limits.max_checkpoint_bytes)?.digest();
        let journal = Journal::open(path, IncompleteTailPolicy::Reject)?;
        if journal.last_root() != expected_root || journal.committed_len() != report.committed_len() {
            return Err(DurableSessionError::RootMismatch);
        }
        Ok(Self {
            journal, memory, checkpoint_digest, limits, records: report.records().len(),
            fenced: false, pending: None, coordination,
        })
    }

    /// Validates every complete record without creating, truncating, or synchronizing the file.
    pub fn inspect(path: impl AsRef<Path>, limits: DurableSessionLimits) -> Result<SessionJournalInspection, DurableSessionError> {
        Self::inspect_with_coordination_ceiling(path.as_ref(), limits, None)
    }

    fn inspect_with_coordination_ceiling(
        path: &Path,
        limits: DurableSessionLimits,
        claim_ceilings: Option<WorkClaimLimits>,
    ) -> Result<SessionJournalInspection, DurableSessionError> {
        let report = read_report(path, limits)?;
        let (memory, _) = replay(&report, limits, claim_ceilings)?;
        Ok(SessionJournalInspection {
            root: report.last_root(),
            checkpoint_digest: memory.checkpoint(limits.max_checkpoint_bytes)?.digest(),
            records: report.records().len(), committed_bytes: report.committed_len(),
            incomplete_tail: report.incomplete_tail(),
        })
    }

    /// Latest known committed prefix root. While fenced this is not a claim about the pending tip.
    #[must_use]
    pub fn committed_root(&self) -> ContentDigest { self.journal.last_root() }

    /// Whether any session operation is currently withheld pending recovery.
    #[must_use]
    pub const fn needs_reconciliation(&self) -> bool { self.fenced }

    /// Backing path, for the trusted persistence owner only.
    #[must_use]
    pub fn path(&self) -> &Path { self.journal.path() }

    /// Verifies the complete bounded history against this handle, not only the final trailer.
    pub fn verify_storage(&self) -> Result<SessionJournalInspection, DurableSessionError> {
        if self.fenced { return Err(DurableSessionError::ReconciliationRequired); }
        let inspection = Self::inspect_with_coordination_ceiling(
            self.path(), self.limits, self.coordination.as_ref().map(|state| state.limits),
        )?;
        if inspection.root != self.committed_root()
            || inspection.committed_bytes != self.journal.committed_len()
            || inspection.incomplete_tail.is_some()
            || inspection.checkpoint_digest != self.checkpoint_digest
        {
            return Err(DurableSessionError::RootMismatch);
        }
        Ok(inspection)
    }

    /// Opens a projected session, preserving exact retry and tombstone semantics.
    pub fn open(&mut self, params: AgentSessionParams, basis: ContractBasis, now: TimestampNs) -> Result<AgentSession, DurableSessionError> {
        self.transact(|store| store.open(params, basis, now))
    }

    /// Reads session state and durably records any new clock watermark or expiry tombstone.
    pub fn session(&mut self, principal: &PrincipalId, session_id: &SessionId, now: TimestampNs) -> Result<AgentSession, DurableSessionError> {
        self.transact(|store| store.session(principal, session_id, now))
    }

    /// Binds an exact authorized descriptor and commits its slot before returning the alias.
    pub fn bind(&mut self, principal: &PrincipalId, request: &SessionBindingRequest, catalog: &ReferenceHydrationCatalog, now: TimestampNs) -> Result<SessionAlias, DurableSessionError> {
        self.transact(|store| store.bind(principal, request, catalog, now))
    }

    /// Revalidates an alias against the current catalog and projected authority.
    pub fn resolve(&mut self, principal: &PrincipalId, alias: &SessionAlias, catalog: &ReferenceHydrationCatalog, now: TimestampNs) -> Result<ResolvedSessionHandle, DurableSessionError> {
        self.transact(|store| store.resolve(principal, alias, catalog, now))
    }

    /// Commits generation invalidation without renewing the lease or replenishing tokens.
    pub fn rotate_symbols(&mut self, principal: &PrincipalId, session_id: &SessionId, generation: u64, now: TimestampNs) -> Result<AgentSession, DurableSessionError> {
        self.transact(|store| store.rotate_symbols(principal, session_id, generation, now))
    }

    /// Commits authority narrowing and anchor refresh before publishing the updated session.
    pub fn refresh(&mut self, principal: &PrincipalId, session_id: &SessionId, refresh: SessionRefresh, now: TimestampNs) -> Result<AgentSession, DurableSessionError> {
        self.transact(|store| store.refresh(principal, session_id, refresh, now))
    }

    /// Durably closes a session; does not cancel, retry, or authorize external effects.
    pub fn close(&mut self, principal: &PrincipalId, session_id: &SessionId, now: TimestampNs) -> Result<(), DurableSessionError> {
        self.transact(|store| store.close(principal, session_id, now))
    }

    /// Reads the cumulative remaining grant without bypassing persistence or principal checks.
    pub fn remaining_token_budget(&mut self, principal: &PrincipalId, session_id: &SessionId, now: TimestampNs) -> Result<u64, DurableSessionError> {
        self.transact(|store| store.remaining_token_budget(principal, session_id, now))
    }

    /// Withholds delivered bytes and catalog mutations until the quoted token charge is durable.
    ///
    /// The catalog is separately owned, bounded reference state, and is cloned for staging. This
    /// does NOT make catalog cursors durable. The owner must retain/recover their replay tombstones
    /// separately. An ambiguous append may commit a charge without delivering a response; recovery
    /// does not refund it or automatically retry. A later explicit retry may incur another charge.
    pub fn hydrate(&mut self, principal: &PrincipalId, alias: &SessionAlias, request: &HydrationRequest, catalog: &mut ReferenceHydrationCatalog, now: TimestampNs) -> Result<HydrationResponse, DurableSessionError> {
        if self.fenced { return Err(DurableSessionError::ReconciliationRequired); }
        let mut staged = catalog.clone();
        let response = self.transact(|store| store.hydrate(principal, alias, request, &mut staged, now))?;
        *catalog = staged;
        Ok(response)
    }

    /// Classifies exactly the pending append, never guesses a failed write was uncommitted.
    ///
    /// Truncation is only allowed when the owner explicitly supplies `Truncate`; all complete
    /// records are validated first. This does not redeliver a withheld response or refund tokens.
    pub fn reconcile_pending(&mut self, tail_policy: IncompleteTailPolicy) -> Result<SessionAppendRecovery, DurableSessionError> {
        if !self.fenced || self.pending.is_none() || self.journal.pending_sequence().is_none() {
            return Err(DurableSessionError::ReconciliationRequired);
        }
        let report = read_report(self.path(), self.limits)?;
        let ceilings = self.pending.as_ref()
            .and_then(|pending| pending.coordination.as_ref())
            .or(self.coordination.as_ref()).map(|state| state.limits);
        replay(&report, self.limits, ceilings)?;
        match self.journal.reconcile_pending(tail_policy)? {
            AppendReconciliation::Committed(record) => {
                let pending = self.pending.as_ref().ok_or(DurableSessionError::ReconciliationRequired)?;
                if record.kind() != pending.kind()
                    || record.payload_digest() != ContentDigest::sha256(pending.payload())
                    || record.payload() != pending.payload()
                {
                    return Err(DurableSessionError::InvalidHistory);
                }
                self.install_pending()?;
                Ok(SessionAppendRecovery::Committed)
            }
            AppendReconciliation::NotCommitted { .. } => {
                self.pending = None;
                self.fenced = false;
                Ok(SessionAppendRecovery::NotCommitted)
            }
        }
    }

    fn transact<T>(&mut self, operation: impl FnOnce(&mut ReferenceSessionStore) -> Result<T, ReferenceSessionError>) -> Result<T, DurableSessionError> {
        self.preflight()?;
        let mut candidate = self.memory.clone();
        let result = operation(&mut candidate);
        let checkpoint = match candidate.checkpoint(self.limits.max_checkpoint_bytes) {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                self.fenced = true;
                return Err(error.into());
            }
        };
        if checkpoint.digest() == self.checkpoint_digest {
            return result.map_err(DurableSessionError::Session);
        }
        self.commit_candidate(PendingSession {
            memory: candidate, checkpoint, coordination: None, record: None,
        })?;
        result.map_err(DurableSessionError::Session)
    }

    fn preflight(&mut self) -> Result<(), DurableSessionError> {
        if self.fenced { return Err(DurableSessionError::ReconciliationRequired); }
        if let Err(error) = self.journal.verify_committed_tail() {
            self.fenced = true;
            return Err(error.into());
        }
        Ok(())
    }

    fn commit_candidate(&mut self, candidate: PendingSession) -> Result<(), DurableSessionError> {
        self.fenced = true;
        check_capacity(self.journal.committed_len(), self.records, candidate.payload().len(), self.limits)?;
        self.pending = Some(candidate);
        let pending = self.pending.as_ref().ok_or(DurableSessionError::ReconciliationRequired)?;
        self.journal.append(pending.kind(), pending.payload())?;
        self.install_pending()
    }

    fn install_pending(&mut self) -> Result<(), DurableSessionError> {
        let next_records = self.records.checked_add(1).ok_or(DurableSessionError::CapacityExceeded)?;
        let pending = self.pending.take().ok_or(DurableSessionError::ReconciliationRequired)?;
        self.memory = pending.memory;
        if let Some(coordination) = pending.coordination {
            self.coordination = Some(coordination);
        }
        self.checkpoint_digest = pending.checkpoint.digest();
        self.records = next_records;
        self.fenced = false;
        Ok(())
    }
}

fn check_capacity(committed: u64, records: usize, payload: usize, limits: DurableSessionLimits) -> Result<(), DurableSessionError> {
    let length = usize::try_from(committed).ok()
        .and_then(|value| value.checked_add(RECORD_OVERHEAD_BYTES))
        .and_then(|value| value.checked_add(payload));
    if records >= limits.max_records
        || length.is_none_or(|value| value > limits.max_journal_bytes.min(MAX_SESSION_JOURNAL_BYTES))
    {
        return Err(DurableSessionError::CapacityExceeded);
    }
    Ok(())
}

fn read_report(path: &Path, limits: DurableSessionLimits) -> Result<RecoveryReport, DurableSessionError> {
    let io = HostJournalReadIo;
    let metadata = io.symlink_metadata(path)?;
    if metadata.is_symlink || !metadata.is_file { return Err(DurableSessionError::InvalidLayout); }
    let limit = limits.max_journal_bytes.min(MAX_SESSION_JOURNAL_BYTES);
    if usize::try_from(metadata.len).ok().is_none_or(|length| length > limit) {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let bytes = io.read_bounded(path, limit.saturating_add(1))?;
    if bytes.len() > limit { return Err(DurableSessionError::CapacityExceeded); }
    let report = recover_bytes(&bytes)?;
    if report.records().len() > limits.max_records { return Err(DurableSessionError::CapacityExceeded); }
    Ok(report)
}

fn replay(
    report: &RecoveryReport,
    limits: DurableSessionLimits,
    claim_ceilings: Option<WorkClaimLimits>,
) -> Result<(ReferenceSessionStore, Option<CoordinationState>), DurableSessionError> {
    DurableSessionStore::verify_source_charge_links(report)?;
    let mut memory: Option<ReferenceSessionStore> = None;
    let mut coordination: Option<CoordinationState> = None;
    let mut cursor_history = None;
    for record in report.records() {
        match record.kind() {
            SESSION_CHECKPOINT_RECORD_KIND => {
                let candidate = disclosure::restore_record(
                    record.payload(), record.payload_digest(), memory.as_ref(), &mut cursor_history, limits,
                )?;
                if memory.as_ref().is_some_and(|previous| previous.limits != candidate.limits) {
                    return Err(DurableSessionError::InvalidHistory);
                }
                memory = Some(candidate);
            }
            coordination::COORDINATION_INIT_RECORD_KIND => {
                // Explicit one-way adoption. A second initialization would erase every fence.
                if coordination.is_some() { return Err(DurableSessionError::InvalidHistory); }
                let sessions = memory.as_ref().ok_or(DurableSessionError::InvalidHistory)?;
                let ceiling = claim_ceilings.ok_or(DurableSessionError::InvalidHistory)?;
                coordination = Some(coordination::restore_initialization(
                    record.payload(), sessions.checkpoint(limits.max_checkpoint_bytes)?.digest(), ceiling,
                )?);
            }
            coordination::COORDINATION_COMMAND_RECORD_KIND => {
                let sessions = memory.as_mut().ok_or(DurableSessionError::InvalidHistory)?;
                let state = coordination.as_mut().ok_or(DurableSessionError::InvalidHistory)?;
                coordination::replay_command(record.payload(), sessions, state, limits)?;
            }
            _ => return Err(DurableSessionError::InvalidHistory),
        }
    }
    Ok((memory.ok_or(DurableSessionError::InvalidHistory)?, coordination))
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;