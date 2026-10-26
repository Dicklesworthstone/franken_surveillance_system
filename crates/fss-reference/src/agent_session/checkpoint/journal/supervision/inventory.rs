#![forbid(unsafe_code)]
//! Authenticated discovery of retained supervision progress without private presentation.

use fss_core::AgentSession;

use super::*;
use crate::agent_session::ReferenceSessionError;

/// Metadata for a historical pending report, without its payload or source inventory.
///
/// These receipts identify retained work. They neither establish current source custody nor
/// authorize release, acknowledgement, discard, progression or any external effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingSupervisionInventory {
    /// Exact durable delivery receipt required by a later explicit terminal operation.
    pub receipt: ContentDigest,
    /// Native supervisor's original semantic report receipt.
    pub report_receipt: ContentDigest,
    /// Original analysis anchor, never replaced with the current session anchor.
    pub anchor: LedgerAnchor,
    /// Digest of the complete retained presentation, never its bytes.
    pub payload_digest: ContentDigest,
    /// Complete retained presentation length, without truncation or disclosure.
    pub payload_len: usize,
    /// Original cumulative schedule prefix; None denotes an unscheduled subscription.
    pub active_window_count: Option<u32>,
    /// Whether the historical anchor shares the live session's interpretation generations.
    /// True does not establish that the source objects remain available or unchanged.
    pub generations_current: bool,
}

/// Bounded metadata for one subscription owned by the admitted live session.
///
/// There is deliberately no configuration, report payload, source identity, or source inventory
/// field. Historical state remains discoverable after a narrower grant refresh when every
/// supervision metadata capability and the private-property scope is still present. Such a
/// subscription is marked with `authority_current = false`; this does not relax any operation's
/// existing exact-authority gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionInventoryEntry {
    /// Session-local identity, in deterministic ascending order within an inventory.
    pub subscription_id: String,
    /// Exact persisted subscription state, including retained progress and lifetime charges.
    pub state_digest: ContentDigest,
    /// Original authority projection under which the subscription was registered.
    pub authority_digest: ContentDigest,
    /// Whether that original projection equals the admitted live session's projection.
    pub authority_current: bool,
    /// Digest of the exact immutable configuration bytes, without disclosing those bytes.
    pub configuration_digest: ContentDigest,
    /// Conservative stored-object bytes reserved for each work attempt.
    pub max_read_bytes: u64,
    /// Conservative indexed object reads reserved for each work attempt.
    pub max_read_attempts: u64,
    /// Finite lifetime evaluation and revalidation allowance.
    pub maximum_attempts: u32,
    /// Complete retained private-report capacity.
    pub max_report_bytes: usize,
    /// Lifetime charged attempts, including unsuccessful or interrupted work.
    pub attempts_reserved: u32,
    /// Lifetime charged bytes; failed and abandoned attempts are never refunded.
    pub reserved_bytes: u64,
    /// Lifetime charged indexed reads, without refunds.
    pub reserved_read_attempts: u64,
    /// Current unfinished charged attempt, retaining its original ordinal, anchor and receipt.
    pub reservation: Option<SupervisionReservation>,
    /// Interpretation-generation comparison for that unfinished attempt, when present.
    pub reservation_generations_current: Option<bool>,
    /// Historical pending-report metadata only.
    pub pending: Option<PendingSupervisionInventory>,
    /// Exact schedule progress, current terminal disposition and latest advance receipt.
    pub schedule: Option<SupervisionSchedule>,
    /// Most recent explicit acknowledgement; inspection never acknowledges a delivery.
    pub last_acknowledged: Option<ContentDigest>,
    /// Most recent explicit discard, kept distinct from acknowledgement.
    pub last_discarded: Option<ContentDigest>,
}

impl SupervisionInventoryEntry {
    fn from_state(
        state: &SupervisionSubscription,
        authority_digest: ContentDigest,
        live_anchor: &LedgerAnchor,
    ) -> Self {
        let registration = &state.registration;
        Self {
            subscription_id: registration.subscription_id.clone(),
            state_digest: state.digest(),
            authority_digest: state.authority_digest,
            authority_current: state.authority_digest == authority_digest,
            configuration_digest: registration.configuration_digest,
            max_read_bytes: registration.max_read_bytes,
            max_read_attempts: registration.max_read_attempts,
            maximum_attempts: registration.maximum_attempts,
            max_report_bytes: registration.max_report_bytes,
            attempts_reserved: state.attempts_reserved,
            reserved_bytes: state.reserved_bytes,
            reserved_read_attempts: state.reserved_read_attempts,
            reservation: state.reservation.clone(),
            reservation_generations_current: state.reservation.as_ref()
                .map(|reservation| same_generations(&reservation.anchor, live_anchor)),
            pending: state.pending.as_ref().map(|pending| PendingSupervisionInventory {
                receipt: pending.receipt,
                report_receipt: pending.report_receipt,
                anchor: pending.anchor.clone(),
                payload_digest: pending.payload_digest,
                payload_len: pending.payload.len(),
                active_window_count: pending.active_window_count,
                generations_current: same_generations(&pending.anchor, live_anchor),
            }),
            schedule: state.schedule.clone(),
            last_acknowledged: state.last_acknowledged,
            last_discarded: state.last_discarded,
        }
    }
}

/// Check the supplied live session against the authoritative record without observing a new
/// clock value, closing an expired identity, renewing authority or changing any session budget.
fn live_authority(
    memory: &ReferenceSessionStore,
    session: &AgentSession,
    now: TimestampNs,
) -> Result<(ContentDigest, LedgerAnchor)> {
    let entry = memory.sessions.get(&session.session_id)
        .filter(|entry| entry.session.principal_id == session.principal_id && !entry.closed)
        .ok_or(DurableSessionError::Session(ReferenceSessionError::Unavailable))?;
    if now < entry.last_observed_at {
        return Err(DurableSessionError::Session(ReferenceSessionError::ClockRegression).into());
    }
    if now.0 >= entry.session.expires_at_ns {
        return Err(DurableSessionError::Session(ReferenceSessionError::Unavailable).into());
    }
    // Comparing every negotiated field rejects caller-forged grants, anchors, budgets and
    // generations even when the session and principal names match an existing record.
    if entry.session != *session {
        return Err(DurableSupervisionError::StaleScope);
    }
    authority_projection(entry)
}

impl DurableSessionStore {
    /// Discover all retained subscriptions for an already authenticated live session.
    ///
    /// The exact supplied session must match its current persisted record, including principal,
    /// capabilities, privacy, anchor and symbol generation. The complete bounded journal is
    /// verified against this handle before any metadata is returned. Another session's names,
    /// configurations, source inventory and private report bytes are never projected.
    ///
    /// At most `MAX_SESSION_SUPERVISION_SUBSCRIPTIONS` entries are returned in ascending
    /// subscription-id order. Inspection writes no record, spends no token or work allowance,
    /// reserves no attempt and changes no pending delivery. Time is checked against the latest
    /// persisted observation without advancing it; normal session operations retain their
    /// existing durable clock and expiry semantics.
    pub fn supervision_inventory(
        &self,
        session: &AgentSession,
        now: TimestampNs,
    ) -> Result<Vec<SupervisionInventoryEntry>> {
        if self.fenced {
            return Err(DurableSessionError::ReconciliationRequired.into());
        }
        // Establish the existing capability and privacy boundary before touching the journal.
        live_authority(&self.memory, session, now)?;
        let report = super::super::read_report(self.path(), self.limits)?;
        if report.last_root() != self.committed_root()
            || report.committed_len() != self.journal.committed_len()
            || report.incomplete_tail().is_some()
        {
            return Err(DurableSessionError::RootMismatch.into());
        }
        let ceilings = self.coordination.as_ref().map(|state| state.limits);
        let restored = super::super::replay_all(&report, self.limits, ceilings)?;
        if restored.memory.checkpoint(self.limits.max_checkpoint_bytes)
            .map_err(DurableSessionError::from)?.digest() != self.checkpoint_digest
        {
            return Err(DurableSessionError::InvalidHistory.into());
        }
        project_inventory(&restored, session, now)
    }
}


pub(crate) fn project_inventory(
    restored: &super::super::ReplayedSessionState,
    session: &AgentSession,
    now: TimestampNs,
) -> Result<Vec<SupervisionInventoryEntry>> {
    let (authority_digest, live_anchor) = live_authority(&restored.memory, session, now)?;
    let mut entries = Vec::new();
    for ((owner, _), state) in &restored.supervisions.subscriptions {
        if owner != &session.session_id { continue; }
        if entries.len() >= MAX_SESSION_SUPERVISION_SUBSCRIPTIONS {
            return Err(DurableSupervisionError::CapacityExceeded);
        }
        entries.push(SupervisionInventoryEntry::from_state(state, authority_digest, &live_anchor));
    }
    Ok(entries)
}
