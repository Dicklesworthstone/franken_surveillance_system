#![forbid(unsafe_code)]
//! Bounded retained-supervision continuity in the existing session journal.
//!
//! This owner retains private historical presentation, exact source inventory and acknowledgement
//! progress. It does not interpret detector scores or certify the caller's native analysis.
//! Deployment composition must verify current source custody before releasing or acknowledging a
//! pending report. Every actual evaluation or source revalidation consumes a full, durable attempt
//! allowance before work starts; failed or abandoned attempts are never refunded.

use std::collections::BTreeMap;
use std::fmt;

use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm, EventId, LedgerAnchor,
    PrincipalId, SessionId, TimestampNs,
};

use super::{DurableSessionError, DurableSessionLimits, DurableSessionStore, PendingSession};
use crate::agent_session::{ReferenceSessionStore, SessionEntry};

mod codec;
mod inventory;
mod projection_charge;
pub(super) use inventory::project_inventory;

pub use inventory::{PendingSupervisionInventory, SupervisionInventoryEntry};

/// Additive session journal kind. Older readers refuse instead of dropping supervision progress.
pub const SUPERVISION_COMMAND_RECORD_KIND: u16 = 0x5356;
/// Maximum immutable configuration bytes, before allocation or canonical encoding.
pub const MAX_SUPERVISION_CONFIGURATION_BYTES: usize = 256 * 1024;
/// Complete private report ceiling. Reports are never truncated.
pub const MAX_SUPERVISION_REPORT_BYTES: usize = 2 * 1024 * 1024;
/// Complete command ceiling, including source inventory and journal command metadata.
pub const MAX_SUPERVISION_RECORD_BYTES: usize = 4 * 1024 * 1024;
/// Complete metadata/native source inventory ceiling.
pub const MAX_SUPERVISION_SOURCES: usize = 4096;
/// Finite lifetime work attempts, including failed evaluations and pending-report revalidation.
pub const MAX_SUPERVISION_ATTEMPTS: u32 = 64;
/// Maximum predeclared cumulative windows in one optional immutable schedule.
pub const MAX_SUPERVISION_WINDOWS: u32 = 32;
/// Retained subscriptions across all sessions, including historical closed owners.
pub const MAX_SUPERVISION_SUBSCRIPTIONS: usize = 64;
/// One session cannot monopolize the retained subscription inventory.
pub const MAX_SESSION_SUPERVISION_SUBSCRIPTIONS: usize = 8;
const MAX_SUBSCRIPTION_BYTES: usize = 128;
const MAX_EVENT_ID_BYTES: usize = 256;
const MAX_ATTEMPT_READ_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ATTEMPT_READS: u64 = 100_000;
const STATE_DOMAIN: &str = "fss.reference_supervision_state.v1";
const AUTHORITY_DOMAIN: &str = "fss.reference_supervision_authority.v1";
const RESERVATION_DOMAIN: &str = "fss.reference_supervision_reservation.v1";
const DELIVERY_DOMAIN: &str = "fss.reference_supervision_delivery.v1";
const EVENT_HEALTH_DELIVERY_DOMAIN: &str = "fss.reference_supervision_event_health_delivery.v1";
const DETECTION_DELIVERY_DOMAIN: &str = "fss.reference_supervision_detection_delivery.v1";
const SCHEDULED_STATE_DOMAIN: &str = "fss.reference_supervision_scheduled_state.v1";
const ADVANCE_DOMAIN: &str = "fss.reference_supervision_window_advance.v1";

/// Refusals never include private report bytes or a hidden subscription's identity.
#[derive(Debug)]
pub enum DurableSupervisionError {
    /// Existing session authority, persistence, capacity or reconciliation refused.
    Session(Box<DurableSessionError>),
    /// Invalid bounded configuration, source inventory, digest or label.
    InvalidRequest,
    /// The live session authority projection or interpretation generations changed.
    StaleScope,
    /// The exact subscription revision, reservation, report or receipt differs.
    Conflict,
    /// Retained inventory, lifetime attempts or complete command capacity was exhausted.
    CapacityExceeded,
}

impl fmt::Display for DurableSupervisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Session(_) => "durable supervision session or journal refused",
            Self::InvalidRequest => "invalid bounded supervision request",
            Self::StaleScope => "supervision session authority projection changed",
            Self::Conflict => "supervision revision, reservation or receipt differs",
            Self::CapacityExceeded => "durable supervision capacity exhausted",
        })
    }
}
impl std::error::Error for DurableSupervisionError {}
impl From<DurableSessionError> for DurableSupervisionError {
    fn from(error: DurableSessionError) -> Self {
        Self::Session(Box::new(error))
    }
}
type Result<T> = std::result::Result<T, DurableSupervisionError>;

fn sha(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256 && digest.bytes() != [0; 32]
}
fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SUBSCRIPTION_BYTES
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}
fn hash(domain: &str, encode: impl FnOnce(&mut CanonicalEncoder)) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(domain);
    encode(&mut e);
    ContentDigest::sha256(&e.finish())
}
fn same_generations(a: &LedgerAnchor, b: &LedgerAnchor) -> bool {
    a.site_lineage == b.site_lineage
        && a.ledger_epoch == b.ledger_epoch
        && a.adapter_registry_epoch == b.adapter_registry_epoch
        && a.schema_epoch == b.schema_epoch
        && a.policy_epoch == b.policy_epoch
        && a.privacy_epoch == b.privacy_epoch
}

/// Immutable finite supervision scope and lifetime work allowance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionRegistration {
    /// Existing authenticated session; this request never creates or renews it.
    pub session_id: SessionId,
    /// Session-local identity, never a filesystem path.
    pub subscription_id: String,
    /// Exact original digest-pinned configuration bytes, interpreted by the native caller.
    pub configuration: Vec<u8>,
    /// SHA-256 of the exact configuration bytes, distinct from any semantic plan digest.
    pub configuration_digest: ContentDigest,
    /// Conservative stored-object bytes reserved for each actual work attempt.
    pub max_read_bytes: u64,
    /// Conservative indexed object-read attempts reserved for each actual work attempt.
    pub max_read_attempts: u64,
    /// Lifetime evaluations/revalidations, including unsuccessful or abandoned attempts.
    pub maximum_attempts: u32,
    /// Complete retained private report bound.
    pub max_report_bytes: usize,
}

impl SupervisionRegistration {
    /// Check all immutable bounds before any session or journal I/O.
    pub fn validate(&self) -> Result<()> {
        if !label(&self.subscription_id)
            || self.configuration.is_empty()
            || self.configuration.len() > MAX_SUPERVISION_CONFIGURATION_BYTES
            || ContentDigest::sha256(&self.configuration) != self.configuration_digest
            || !sha(self.configuration_digest)
            || !(1..=MAX_ATTEMPT_READ_BYTES).contains(&self.max_read_bytes)
            || !(1..=MAX_ATTEMPT_READS).contains(&self.max_read_attempts)
            || !(1..=MAX_SUPERVISION_ATTEMPTS).contains(&self.maximum_attempts)
            || !(1..=MAX_SUPERVISION_REPORT_BYTES).contains(&self.max_report_bytes)
        {
            return Err(DurableSupervisionError::InvalidRequest);
        }
        Ok(())
    }

    fn encode_identity(&self, e: &mut CanonicalEncoder) {
        e.text(self.session_id.as_str());
        e.text(&self.subscription_id);
        e.digest(self.configuration_digest);
        e.u64(self.max_read_bytes);
        e.u64(self.max_read_attempts);
        e.u32(self.maximum_attempts);
        e.u64(self.max_report_bytes as u64);
    }

    fn encode(&self, e: &mut CanonicalEncoder) {
        e.text(self.session_id.as_str());
        e.text(&self.subscription_id);
        e.bytes(&self.configuration);
        e.digest(self.configuration_digest);
        e.u64(self.max_read_bytes);
        e.u64(self.max_read_attempts);
        e.u32(self.maximum_attempts);
        e.u64(self.max_report_bytes as u64);
    }
}

/// One exact current event metadata root consulted by the native discovery owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionSourcePin {
    /// Exact registered package-event identity.
    pub event_id: EventId,
    /// Root binds the metadata bytes; source availability remains current at every release.
    pub event_root: ContentDigest,
    /// True only when the native owner reopened the complete source, including excluded sources.
    pub source_verified: bool,
    /// Exact selected-row health interpretation. Legacy unassessed deliveries retain None;
    /// the native owner must refuse their release when selected rows require a health pin.
    pub health_digest: Option<ContentDigest>,
}

impl SupervisionSourcePin {
    fn encode(&self, e: &mut CanonicalEncoder) {
        e.text(self.event_id.as_str());
        e.digest(self.event_root);
        e.bool(self.source_verified);
    }
}

/// Exact native detector metadata and its independently verified source interpretation.
///
/// These identities are distinct from package-event pins. Retaining them grants no evidence
/// authority: the native caller must reopen the complete source and health view on every release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionDetectionSourcePin {
    /// Exact retained native detector report selected by discovery.
    pub report_digest: ContentDigest,
    /// Exact canonical native detection record.
    pub record_digest: ContentDigest,
    /// Exact source-closed detection provenance root.
    pub detection_root: ContentDigest,
    /// True only when the native caller verified the complete underlying source.
    pub source_verified: bool,
    /// Optional digest of the complete source-bound historical health assessment.
    /// Its presence requires native source verification; it grants no health certificate.
    pub health_digest: Option<ContentDigest>,
}

impl SupervisionDetectionSourcePin {
    fn encode(&self, e: &mut CanonicalEncoder) {
        e.digest(self.report_digest);
        e.digest(self.record_digest);
        e.digest(self.detection_root);
        e.bool(self.source_verified);
        optional_digest(e, self.health_digest);
    }
}

/// One charged work attempt. Completion consumes its token; abandoning it never refunds costs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionReservation {
    ordinal: u32,
    anchor: LedgerAnchor,
    receipt: ContentDigest,
}

impl SupervisionReservation {
    /// Exact one-use work reservation.
    pub const fn receipt(&self) -> ContentDigest {
        self.receipt
    }
    /// Explicit current authority under which this attempt was admitted.
    pub const fn anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
    /// One-based lifetime attempt index.
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }
    fn encode(&self, e: &mut CanonicalEncoder) {
        e.u32(self.ordinal);
        self.anchor.encode_canonical(e);
        e.digest(self.receipt);
    }
}

/// The most recent explicit progression, retained for safe lost-response retries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionAdvance {
    target_count: u32,
    after_receipt: ContentDigest,
    receipt: ContentDigest,
}

impl SupervisionAdvance {
    /// One-based size of the cumulative prefix activated by this transition.
    pub const fn target_count(&self) -> u32 {
        self.target_count
    }
    /// Exact prior delivery explicitly acknowledged or discarded before progression.
    pub const fn after_receipt(&self) -> ContentDigest {
        self.after_receipt
    }
    /// Receipt binding prior state, terminal delivery and admitted current authority.
    pub const fn receipt(&self) -> ContentDigest {
        self.receipt
    }
    fn encode(&self, e: &mut CanonicalEncoder) {
        e.u32(self.target_count);
        e.digest(self.after_receipt);
        e.digest(self.receipt);
    }
}

/// Durable progress through the cumulative windows in the exact original configuration.
///
/// Configuration bytes already bind every endpoint and policy choice. The native adapter
/// checks this count against that plan; the journal cannot reinterpret opaque configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionSchedule {
    total_windows: u32,
    active_window_count: u32,
    resolved_receipt: Option<ContentDigest>,
    resolved_acknowledged: Option<bool>,
    last_advance: Option<SupervisionAdvance>,
}

impl SupervisionSchedule {
    fn new(total_windows: u32) -> Self {
        Self {
            total_windows,
            active_window_count: 1,
            resolved_receipt: None,
            resolved_acknowledged: None,
            last_advance: None,
        }
    }
    /// Complete immutable number of predeclared windows.
    pub const fn total_windows(&self) -> u32 {
        self.total_windows
    }
    /// Current cumulative prefix; earlier windows are never removed or renumbered.
    pub const fn active_window_count(&self) -> u32 {
        self.active_window_count
    }
    /// Current-prefix terminal delivery, cleared when another report is published.
    pub const fn resolved_receipt(&self) -> Option<ContentDigest> {
        self.resolved_receipt
    }
    /// True means ACK; false means explicit discard. Rendering creates neither.
    pub const fn resolved_acknowledged(&self) -> Option<bool> {
        self.resolved_acknowledged
    }
    /// Most recent exact progression, even when its successor report is already pending.
    pub const fn last_advance(&self) -> Option<&SupervisionAdvance> {
        self.last_advance.as_ref()
    }
    fn encode(&self, e: &mut CanonicalEncoder) {
        e.u32(self.total_windows);
        e.u32(self.active_window_count);
        optional_digest(e, self.resolved_receipt);
        e.bool(self.resolved_acknowledged.is_some());
        if let Some(acknowledged) = self.resolved_acknowledged {
            e.bool(acknowledged);
        }
        e.bool(self.last_advance.is_some());
        if let Some(advance) = &self.last_advance {
            advance.encode(e);
        }
    }
    fn resolve(&mut self, receipt: ContentDigest, acknowledged: bool) {
        self.resolved_receipt = Some(receipt);
        self.resolved_acknowledged = Some(acknowledged);
    }
}

/// Descriptor of retained historical cognition. There is deliberately no private payload getter.
#[derive(Clone, Eq, PartialEq)]
pub struct PendingSupervisionDelivery {
    anchor: LedgerAnchor,
    sources: Vec<SupervisionSourcePin>,
    detection_sources: Vec<SupervisionDetectionSourcePin>,
    payload: Vec<u8>,
    payload_digest: ContentDigest,
    report_receipt: ContentDigest,
    receipt: ContentDigest,
    // Derived at Publish; its current-state digest already seals this original prefix.
    active_window_count: Option<u32>,
}

impl fmt::Debug for PendingSupervisionDelivery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingSupervisionDelivery")
            .field("anchor", &self.anchor)
            .field("source_count", &self.sources.len())
            .field("detection_source_count", &self.detection_sources.len())
            .field("payload_len", &self.payload.len())
            .field("payload_digest", &self.payload_digest)
            .field("report_receipt", &self.report_receipt)
            .field("receipt", &self.receipt)
            .field("active_window_count", &self.active_window_count)
            .finish()
    }
}

impl PendingSupervisionDelivery {
    /// Exact receipt for acknowledgement or explicit invalidation.
    pub const fn receipt(&self) -> ContentDigest {
        self.receipt
    }
    /// Native supervisor's semantic report receipt, distinct from stored JSON identity.
    pub const fn report_receipt(&self) -> ContentDigest {
        self.report_receipt
    }
    /// Original historical analysis authority, never silently replaced on redelivery.
    pub const fn anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
    /// Complete original metadata and source inventory, including exclusions.
    pub fn source_inventory(&self) -> &[SupervisionSourcePin] {
        &self.sources
    }
    /// Complete original native detector inventory, including metadata-only exclusions.
    /// A nonempty inventory is mutually exclusive with package-event source pins.
    pub fn detection_source_inventory(&self) -> &[SupervisionDetectionSourcePin] {
        &self.detection_sources
    }
    /// Exact identity of the retained private bytes.
    pub const fn payload_digest(&self) -> ContentDigest {
        self.payload_digest
    }
    /// Complete private report byte count.
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }
    /// Original cumulative prefix used for this historical report; None is legacy mode.
    pub const fn active_window_count(&self) -> Option<u32> {
        self.active_window_count
    }
    fn encode_descriptor(&self, e: &mut CanonicalEncoder) {
        self.anchor.encode_canonical(e);
        e.u64(self.sources.len() as u64);
        for source in &self.sources {
            source.encode(e);
        }
        e.u64(self.payload.len() as u64);
        e.digest(self.payload_digest);
        e.digest(self.report_receipt);
    }

    fn delivery_receipt(&self, state: ContentDigest, reservation: ContentDigest) -> ContentDigest {
        let event_health = self
            .sources
            .iter()
            .any(|source| source.health_digest.is_some());
        let domain = if !self.detection_sources.is_empty() {
            DETECTION_DELIVERY_DOMAIN
        } else if event_health {
            EVENT_HEALTH_DELIVERY_DOMAIN
        } else {
            DELIVERY_DOMAIN
        };
        hash(domain, |e| {
            e.digest(state);
            e.digest(reservation);
            // Legacy unassessed event deliveries remain byte-identical. New health pins are
            // sealed under their own domain without redefining existing journal history.
            self.encode_descriptor(e);
            if event_health {
                for source in &self.sources {
                    optional_digest(e, source.health_digest);
                }
            }
            if !self.detection_sources.is_empty() {
                e.u64(self.detection_sources.len() as u64);
                for source in &self.detection_sources {
                    source.encode(e);
                }
            }
        })
    }
}

/// Historical progress. Its getters grant neither current source access nor effect authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionSubscription {
    registration: SupervisionRegistration,
    authority_digest: ContentDigest,
    revision: u64,
    attempts_reserved: u32,
    reserved_bytes: u64,
    reserved_read_attempts: u64,
    reservation: Option<SupervisionReservation>,
    pending: Option<PendingSupervisionDelivery>,
    last_acknowledged: Option<ContentDigest>,
    last_discarded: Option<ContentDigest>,
    schedule: Option<SupervisionSchedule>,
}

impl SupervisionSubscription {
    /// Immutable original scope, including all frozen read and lifetime bounds.
    pub const fn registration(&self) -> &SupervisionRegistration {
        &self.registration
    }
    /// Number of charged work attempts, including crashed or unsuccessful work.
    pub const fn attempts_reserved(&self) -> u32 {
        self.attempts_reserved
    }
    /// Conservative lifetime bytes charged before native work, without refunds.
    pub const fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }
    /// Conservative lifetime indexed reads charged before native work, without refunds.
    pub const fn reserved_read_attempts(&self) -> u64 {
        self.reserved_read_attempts
    }
    /// Current one-use attempt, if work was reserved but not completed.
    pub const fn reservation(&self) -> Option<&SupervisionReservation> {
        self.reservation.as_ref()
    }
    /// Pending descriptor only; its bytes require live admitted release after source validation.
    pub const fn pending(&self) -> Option<&PendingSupervisionDelivery> {
        self.pending.as_ref()
    }
    /// Most recent exact ACK for safe lost-response retries.
    pub const fn last_acknowledged(&self) -> Option<ContentDigest> {
        self.last_acknowledged
    }
    /// Most recent exact invalidation, never treated as acknowledgement.
    pub const fn last_discarded(&self) -> Option<ContentDigest> {
        self.last_discarded
    }
    /// Optional immutable schedule and its durable active prefix.
    pub const fn schedule(&self) -> Option<&SupervisionSchedule> {
        self.schedule.as_ref()
    }
    /// Prefix for native evaluation; None executes the complete legacy plan.
    pub fn active_window_count(&self) -> Option<u32> {
        self.schedule
            .as_ref()
            .map(SupervisionSchedule::active_window_count)
    }
    /// CAS identity over immutable scope, lifetime charges and every retained progress field.
    pub fn digest(&self) -> ContentDigest {
        // Preserve every legacy byte and digest when no explicit schedule was configured.
        let legacy = hash(STATE_DOMAIN, |e| {
            e.text("subscription");
            self.registration.encode_identity(e);
            e.digest(self.authority_digest);
            e.u64(self.revision);
            e.u32(self.attempts_reserved);
            e.u64(self.reserved_bytes);
            e.u64(self.reserved_read_attempts);
            e.bool(self.reservation.is_some());
            if let Some(r) = &self.reservation {
                r.encode(e);
            }
            e.bool(self.pending.is_some());
            if let Some(p) = &self.pending {
                // Replay reconstructs this receipt from the complete inventory and payload.
                e.digest(p.receipt);
            }
            optional_digest(e, self.last_acknowledged);
            optional_digest(e, self.last_discarded);
        });
        self.schedule.as_ref().map_or(legacy, |schedule| {
            hash(SCHEDULED_STATE_DOMAIN, |e| {
                e.digest(legacy);
                schedule.encode(e);
            })
        })
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct SupervisionState {
    subscriptions: BTreeMap<(SessionId, String), SupervisionSubscription>,
}

impl SupervisionState {
    pub(super) fn retained(&self) -> Vec<SupervisionSubscription> {
        self.subscriptions.values().cloned().collect()
    }
    fn digest(&self) -> ContentDigest {
        hash(STATE_DOMAIN, |e| {
            e.text("store");
            e.u64(self.subscriptions.len() as u64);
            for state in self.subscriptions.values() {
                e.digest(state.digest());
            }
        })
    }
}

#[derive(Clone, Debug)]
enum Command {
    Register(SupervisionRegistration),
    // Admitted state inspection has no transition and is never encoded as a journal record.
    Inspect(SupervisionRegistration),
    // Recover only an existing owner's exact registration; never create or expose report bytes.
    Lookup(String),
    Reserve {
        subscription: String,
        expected: ContentDigest,
        anchor: LedgerAnchor,
    },
    Publish {
        subscription: String,
        expected: ContentDigest,
        reservation: ContentDigest,
        payload: Vec<u8>,
        sources: Vec<SupervisionSourcePin>,
        detection_sources: Vec<SupervisionDetectionSourcePin>,
        report_receipt: ContentDigest,
    },
    Release {
        subscription: String,
        expected: ContentDigest,
        reservation: ContentDigest,
        receipt: ContentDigest,
    },
    Acknowledge {
        subscription: String,
        expected: ContentDigest,
        reservation: Option<ContentDigest>,
        receipt: ContentDigest,
        anchor: LedgerAnchor,
    },
    Discard {
        subscription: String,
        expected: ContentDigest,
        receipt: ContentDigest,
        anchor: LedgerAnchor,
    },
    ConfigureSchedule {
        registration: SupervisionRegistration,
        total_windows: u32,
    },
    Advance {
        subscription: String,
        expected: ContentDigest,
        target_count: u32,
        after_receipt: ContentDigest,
        anchor: LedgerAnchor,
    },
}

impl Command {
    fn subscription(&self) -> &str {
        match self {
            Self::Register(r) => &r.subscription_id,
            Self::Inspect(r) => &r.subscription_id,
            Self::Lookup(subscription) => subscription,
            Self::ConfigureSchedule { registration, .. } => &registration.subscription_id,
            Self::Reserve { subscription, .. }
            | Self::Publish { subscription, .. }
            | Self::Release { subscription, .. }
            | Self::Acknowledge { subscription, .. }
            | Self::Discard { subscription, .. }
            | Self::Advance { subscription, .. } => subscription,
        }
    }
}

fn optional_digest(e: &mut CanonicalEncoder, value: Option<ContentDigest>) {
    e.bool(value.is_some());
    if let Some(value) = value {
        e.digest(value);
    }
}

fn authority(
    memory: &mut ReferenceSessionStore,
    principal: &PrincipalId,
    session: &SessionId,
    now: TimestampNs,
) -> Result<(ContentDigest, LedgerAnchor)> {
    let entry = memory
        .live_entry(principal, session, now)
        .map_err(DurableSessionError::Session)?;
    authority_projection(entry)
}

fn authority_projection(entry: &SessionEntry) -> Result<(ContentDigest, LedgerAnchor)> {
    if ![
        "CAP-AGENT-SESSION-READ-001",
        "CAP-AGENT-SESSION-WRITE-001",
        "CAP-AGENT-SITUATION-READ-001",
        "CAP-AGENT-INVESTIGATE-001",
    ]
    .iter()
    .all(|grant| entry.session.capabilities.contains(*grant))
        || !entry.session.privacy_scope.contains("private:property")
    {
        return Err(DurableSupervisionError::StaleScope);
    }
    let digest = hash(AUTHORITY_DOMAIN, |e| {
        e.text(entry.session.principal_id.as_str());
        e.text(entry.session.session_id.as_str());
        e.text(entry.session.mission_id.as_str());
        entry.basis.encode_canonical(e);
        e.i128(entry.session.created_at_ns);
        e.i128(entry.session.expires_at_ns);
        e.u64(entry.session.token_budget);
        for grants in [&entry.session.capabilities, &entry.session.privacy_scope] {
            e.u64(grants.len() as u64);
            for grant in grants {
                e.text(grant);
            }
        }
    });
    Ok((digest, entry.session.current_anchor.clone()))
}

fn checked_reservation<'a>(
    state: &'a SupervisionSubscription,
    receipt: ContentDigest,
    live: &LedgerAnchor,
) -> Result<&'a SupervisionReservation> {
    let reservation = state
        .reservation
        .as_ref()
        .filter(|r| r.receipt == receipt)
        .ok_or(DurableSupervisionError::Conflict)?;
    if !same_generations(live, &reservation.anchor) {
        return Err(DurableSupervisionError::StaleScope);
    }
    Ok(reservation)
}

fn validate_sources(sources: &[SupervisionSourcePin]) -> Result<()> {
    if sources.len() > MAX_SUPERVISION_SOURCES {
        return Err(DurableSupervisionError::CapacityExceeded);
    }
    for source in sources {
        if source.event_id.as_str().len() > MAX_EVENT_ID_BYTES
            || !source.event_id.as_str().starts_with("event:package:")
            || !sha(source.event_root)
            || source
                .health_digest
                .is_some_and(|digest| !source.source_verified || !sha(digest))
        {
            return Err(DurableSupervisionError::InvalidRequest);
        }
    }
    if sources.windows(2).any(|p| p[0].event_id >= p[1].event_id) {
        return Err(DurableSupervisionError::InvalidRequest);
    }
    Ok(())
}

fn validate_source_inventories(
    sources: &[SupervisionSourcePin],
    detection_sources: &[SupervisionDetectionSourcePin],
) -> Result<()> {
    if sources
        .len()
        .checked_add(detection_sources.len())
        .is_none_or(|count| count > MAX_SUPERVISION_SOURCES)
    {
        return Err(DurableSupervisionError::CapacityExceeded);
    }
    if !sources.is_empty() && !detection_sources.is_empty() {
        return Err(DurableSupervisionError::InvalidRequest);
    }
    validate_sources(sources)?;
    for source in detection_sources {
        if !sha(source.report_digest)
            || !sha(source.record_digest)
            || !sha(source.detection_root)
            || source
                .health_digest
                .is_some_and(|digest| !source.source_verified || !sha(digest))
        {
            return Err(DurableSupervisionError::InvalidRequest);
        }
    }
    if detection_sources
        .windows(2)
        .any(|pair| pair[0].report_digest >= pair[1].report_digest)
    {
        return Err(DurableSupervisionError::InvalidRequest);
    }
    Ok(())
}
fn apply(
    memory: &mut ReferenceSessionStore,
    state: &mut SupervisionState,
    principal: &PrincipalId,
    session: &SessionId,
    command: &Command,
    now: TimestampNs,
) -> Result<SupervisionSubscription> {
    let (authority_digest, live_anchor) = authority(memory, principal, session, now)?;
    let key = (session.clone(), command.subscription().to_owned());
    let initialization = match command {
        Command::Register(registration) => Some((registration, None)),
        Command::ConfigureSchedule {
            registration,
            total_windows,
        } => {
            if !(1..=MAX_SUPERVISION_WINDOWS).contains(total_windows) {
                return Err(DurableSupervisionError::InvalidRequest);
            }
            Some((registration, Some(*total_windows)))
        }
        _ => None,
    };
    if let Some((registration, schedule_count)) = initialization {
        registration.validate()?;
        if registration.session_id != *session {
            return Err(DurableSupervisionError::InvalidRequest);
        }
        if let Some(existing) = state.subscriptions.get(&key) {
            if existing.authority_digest != authority_digest {
                return Err(DurableSupervisionError::StaleScope);
            }
            if existing.registration != *registration {
                return Err(DurableSupervisionError::Conflict);
            }
            let Some(total_windows) = schedule_count else {
                return Ok(existing.clone());
            };
            if let Some(schedule) = &existing.schedule {
                return if schedule.total_windows == total_windows {
                    Ok(existing.clone())
                } else {
                    Err(DurableSupervisionError::Conflict)
                };
            }
            if existing.attempts_reserved != 0
                || existing.pending.is_some()
                || existing.reservation.is_some()
                || existing.last_acknowledged.is_some()
                || existing.last_discarded.is_some()
            {
                return Err(DurableSupervisionError::Conflict);
            }
            let mut configured = existing.clone();
            configured.schedule = Some(SupervisionSchedule::new(total_windows));
            configured.revision = existing
                .revision
                .checked_add(1)
                .ok_or(DurableSupervisionError::CapacityExceeded)?;
            state.subscriptions.insert(key, configured.clone());
            return Ok(configured);
        }
        if state.subscriptions.len() >= MAX_SUPERVISION_SUBSCRIPTIONS
            || state
                .subscriptions
                .keys()
                .filter(|(id, _)| id == session)
                .count()
                >= MAX_SESSION_SUPERVISION_SUBSCRIPTIONS
        {
            return Err(DurableSupervisionError::CapacityExceeded);
        }
        let result = SupervisionSubscription {
            registration: registration.clone(),
            authority_digest,
            revision: 0,
            attempts_reserved: 0,
            reserved_bytes: 0,
            reserved_read_attempts: 0,
            reservation: None,
            pending: None,
            last_acknowledged: None,
            last_discarded: None,
            schedule: schedule_count.map(SupervisionSchedule::new),
        };
        state.subscriptions.insert(key, result.clone());
        return Ok(result);
    }
    let current = state
        .subscriptions
        .get(&key)
        .ok_or(DurableSupervisionError::Conflict)?;
    if current.authority_digest != authority_digest {
        return Err(DurableSupervisionError::StaleScope);
    }
    if matches!(command, Command::Lookup(_)) {
        return Ok(current.clone());
    }
    if let Command::Inspect(registration) = command {
        registration.validate()?;
        if registration.session_id != *session || current.registration != *registration {
            return Err(DurableSupervisionError::Conflict);
        }
        return Ok(current.clone());
    }
    let expected = match command {
        Command::Register(_)
        | Command::Inspect(_)
        | Command::Lookup(_)
        | Command::ConfigureSchedule { .. } => return Err(DurableSupervisionError::InvalidRequest),
        Command::Reserve { expected, .. }
        | Command::Publish { expected, .. }
        | Command::Release { expected, .. }
        | Command::Acknowledge { expected, .. }
        | Command::Discard { expected, .. }
        | Command::Advance { expected, .. } => *expected,
    };
    if current.digest() != expected {
        return Err(DurableSupervisionError::Conflict);
    }
    let mut next = current.clone();
    match command {
        Command::Register(_)
        | Command::Inspect(_)
        | Command::Lookup(_)
        | Command::ConfigureSchedule { .. } => return Err(DurableSupervisionError::InvalidRequest),
        Command::Reserve { anchor, .. } => {
            if !same_generations(&live_anchor, anchor) || !sha(anchor.state_root) {
                return Err(DurableSupervisionError::StaleScope);
            }
            let ordinal = current
                .attempts_reserved
                .checked_add(1)
                .filter(|n| *n <= current.registration.maximum_attempts)
                .ok_or(DurableSupervisionError::CapacityExceeded)?;
            let receipt = hash(RESERVATION_DOMAIN, |e| {
                e.digest(current.digest());
                e.u32(ordinal);
                anchor.encode_canonical(e);
                e.u64(current.registration.max_read_bytes);
                e.u64(current.registration.max_read_attempts);
            });
            next.attempts_reserved = ordinal;
            next.reserved_bytes = current
                .reserved_bytes
                .checked_add(current.registration.max_read_bytes)
                .ok_or(DurableSupervisionError::CapacityExceeded)?;
            next.reserved_read_attempts = current
                .reserved_read_attempts
                .checked_add(current.registration.max_read_attempts)
                .ok_or(DurableSupervisionError::CapacityExceeded)?;
            next.reservation = Some(SupervisionReservation {
                ordinal,
                anchor: anchor.clone(),
                receipt,
            });
        }
        Command::Publish {
            reservation,
            payload,
            sources,
            detection_sources,
            report_receipt,
            ..
        } => {
            let reserved = checked_reservation(current, *reservation, &live_anchor)?;
            if current.pending.is_some() {
                return Err(DurableSupervisionError::Conflict);
            }
            if payload.is_empty()
                || payload.len() > current.registration.max_report_bytes
                || !sha(*report_receipt)
            {
                return Err(DurableSupervisionError::InvalidRequest);
            }
            validate_source_inventories(sources, detection_sources)?;
            let mut pending = PendingSupervisionDelivery {
                anchor: reserved.anchor.clone(),
                sources: sources.clone(),
                payload: payload.clone(),
                detection_sources: detection_sources.clone(),
                payload_digest: ContentDigest::sha256(payload),
                report_receipt: *report_receipt,
                receipt: ContentDigest::sha256(b"unsealed supervision delivery"),
                active_window_count: current.active_window_count(),
            };
            pending.receipt = pending.delivery_receipt(current.digest(), *reservation);
            next.pending = Some(pending);
            next.reservation = None;
            if let Some(schedule) = &mut next.schedule {
                schedule.resolved_receipt = None;
                schedule.resolved_acknowledged = None;
            }
        }
        Command::Release {
            reservation,
            receipt,
            ..
        } => {
            checked_reservation(current, *reservation, &live_anchor)?;
            if current
                .pending
                .as_ref()
                .is_none_or(|p| p.receipt != *receipt)
            {
                return Err(DurableSupervisionError::Conflict);
            }
            next.reservation = None;
        }
        Command::Acknowledge {
            reservation,
            receipt,
            anchor,
            ..
        } => {
            if !same_generations(&live_anchor, anchor) || !sha(anchor.state_root) {
                return Err(DurableSupervisionError::StaleScope);
            }
            if current.last_acknowledged == Some(*receipt) {
                return Ok(current.clone());
            }
            let reserved = checked_reservation(
                current,
                reservation.ok_or(DurableSupervisionError::Conflict)?,
                &live_anchor,
            )?;
            if &reserved.anchor != anchor
                || current
                    .pending
                    .as_ref()
                    .is_none_or(|p| p.receipt != *receipt)
            {
                return Err(DurableSupervisionError::Conflict);
            }
            next.pending = None;
            next.reservation = None;
            next.last_acknowledged = Some(*receipt);
            if let Some(schedule) = &mut next.schedule {
                schedule.resolve(*receipt, true);
            }
        }
        Command::Discard {
            receipt, anchor, ..
        } => {
            if !same_generations(&live_anchor, anchor) || !sha(anchor.state_root) {
                return Err(DurableSupervisionError::StaleScope);
            }
            if current.last_discarded == Some(*receipt) {
                return Ok(current.clone());
            }
            if current
                .pending
                .as_ref()
                .is_none_or(|p| p.receipt != *receipt)
            {
                return Err(DurableSupervisionError::Conflict);
            }
            next.pending = None;
            next.reservation = None;
            next.last_discarded = Some(*receipt);
            if let Some(schedule) = &mut next.schedule {
                schedule.resolve(*receipt, false);
            }
        }
        Command::Advance {
            target_count,
            after_receipt,
            anchor,
            ..
        } => {
            if !same_generations(&live_anchor, anchor) || !sha(anchor.state_root) {
                return Err(DurableSupervisionError::StaleScope);
            }
            let schedule = current
                .schedule
                .as_ref()
                .ok_or(DurableSupervisionError::Conflict)?;
            if schedule.last_advance.as_ref().is_some_and(|advance| {
                advance.target_count == *target_count && advance.after_receipt == *after_receipt
            }) {
                // A lost response may be retried after its successor is already pending.
                return Ok(current.clone());
            }
            if current.pending.is_some()
                || !sha(*after_receipt)
                || schedule.active_window_count.checked_add(1) != Some(*target_count)
                || *target_count > schedule.total_windows
                || schedule.resolved_receipt != Some(*after_receipt)
                || schedule.resolved_acknowledged.is_none()
            {
                return Err(DurableSupervisionError::Conflict);
            }
            let receipt = hash(ADVANCE_DOMAIN, |e| {
                e.digest(current.digest());
                e.u32(*target_count);
                e.digest(*after_receipt);
                anchor.encode_canonical(e);
            });
            let schedule = next
                .schedule
                .as_mut()
                .ok_or(DurableSupervisionError::Conflict)?;
            schedule.active_window_count = *target_count;
            schedule.resolved_receipt = None;
            schedule.resolved_acknowledged = None;
            schedule.last_advance = Some(SupervisionAdvance {
                target_count: *target_count,
                after_receipt: *after_receipt,
                receipt,
            });
            // An interrupted repeat after a terminal delivery may leave charged work. Explicit
            // progression abandons that attempt but never refunds its lifetime reservation.
            next.reservation = None;
        }
    }
    next.revision = current
        .revision
        .checked_add(1)
        .ok_or(DurableSupervisionError::CapacityExceeded)?;
    state.subscriptions.insert(key, next.clone());
    Ok(next)
}

impl DurableSessionStore {
    /// Atomically create a scheduled subscription, or configure an exact unused registration.
    ///
    /// Initial configuration and prefix one share a single journal command. A failed creation
    /// cannot leave an unscheduled registration that evaluates the entire future schedule.
    /// Exact configured retries preserve pending reports, terminal receipts and all charges.
    pub fn configure_supervision_schedule(
        &mut self,
        principal: &PrincipalId,
        registration: &SupervisionRegistration,
        total_windows: u32,
        now: TimestampNs,
    ) -> Result<SupervisionSubscription> {
        registration.validate()?;
        if !(1..=MAX_SUPERVISION_WINDOWS).contains(&total_windows) {
            return Err(DurableSupervisionError::InvalidRequest);
        }
        self.supervision_command(
            principal,
            &registration.session_id,
            Command::ConfigureSchedule {
                registration: registration.clone(),
                total_windows,
            },
            now,
        )
    }

    /// Inspect one existing subscription under live session authority without native reads,
    /// registration, publication, acknowledgement, discard or a new attempt reservation.
    /// The result exposes historical descriptors only, never private report bytes.
    pub fn inspect_supervision(
        &mut self,
        principal: &PrincipalId,
        registration: &SupervisionRegistration,
        now: TimestampNs,
    ) -> Result<SupervisionSubscription> {
        registration.validate()?;
        self.supervision_command(
            principal,
            &registration.session_id,
            Command::Inspect(registration.clone()),
            now,
        )
    }

    /// Recover the exact immutable registration through the live owning session and verified
    /// journal. This performs no source work, creates no subscription, and changes no supervision
    /// state or lifetime allowance. Session clock/expiry observations retain their existing
    /// durable semantics. Pending report bytes are never returned by this operation.
    pub fn recover_supervision_registration(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        subscription: &str,
        now: TimestampNs,
    ) -> Result<SupervisionRegistration> {
        if !label(subscription) {
            return Err(DurableSupervisionError::InvalidRequest);
        }
        self.supervision_command(
            principal,
            session,
            Command::Lookup(subscription.to_owned()),
            now,
        )
        .map(|state| state.registration)
    }

    /// Register immutable supervision once; exact retry never resets progress, lease or charges.
    pub fn register_supervision(
        &mut self,
        principal: &PrincipalId,
        registration: SupervisionRegistration,
        now: TimestampNs,
    ) -> Result<SupervisionSubscription> {
        registration.validate()?;
        let session = registration.session_id.clone();
        self.supervision_command(principal, &session, Command::Register(registration), now)
    }

    /// Durably charge one full work allowance before any native evaluation or revalidation.
    ///
    /// Replacing an unfinished reservation records another charged attempt; it never refunds the
    /// earlier attempt. The deployment owner must synchronize its root pin before starting work.
    pub fn reserve_supervision(
        &mut self,
        principal: &PrincipalId,
        state: &SupervisionSubscription,
        current_anchor: &LedgerAnchor,
        now: TimestampNs,
    ) -> Result<SupervisionSubscription> {
        self.supervision_command(
            principal,
            &state.registration.session_id,
            Command::Reserve {
                subscription: state.registration.subscription_id.clone(),
                expected: state.digest(),
                anchor: current_anchor.clone(),
            },
            now,
        )
    }

    /// Retain complete historical cognition before release, consuming the exact work reservation.
    ///
    /// Native analysis and inventory completeness are the caller's responsibility. This structural
    /// journal owner never elevates the presentation bytes or caller's receipt to source truth.
    pub fn publish_supervision(
        &mut self,
        principal: &PrincipalId,
        state: &SupervisionSubscription,
        reservation: &SupervisionReservation,
        payload: Vec<u8>,
        sources: Vec<SupervisionSourcePin>,
        report_receipt: ContentDigest,
        now: TimestampNs,
    ) -> Result<SupervisionSubscription> {
        self.publish_supervision_with_detections(
            principal,
            state,
            reservation,
            payload,
            sources,
            Vec::new(),
            report_receipt,
            now,
        )
    }

    /// Retain a complete native-detector report with exact source and historical-health pins.
    ///
    /// Event and native inventories cannot be mixed. Native inventory completeness and current
    /// verification remain the evaluator's responsibility. Empty native inventory preserves the
    /// original command bytes, delivery receipt and state identity.
    pub fn publish_supervision_with_detections(
        &mut self,
        principal: &PrincipalId,
        state: &SupervisionSubscription,
        reservation: &SupervisionReservation,
        payload: Vec<u8>,
        mut sources: Vec<SupervisionSourcePin>,
        mut detection_sources: Vec<SupervisionDetectionSourcePin>,
        report_receipt: ContentDigest,
        now: TimestampNs,
    ) -> Result<SupervisionSubscription> {
        if payload.len() > MAX_SUPERVISION_REPORT_BYTES
            || sources
                .len()
                .checked_add(detection_sources.len())
                .is_none_or(|count| count > MAX_SUPERVISION_SOURCES)
        {
            return Err(DurableSupervisionError::CapacityExceeded);
        }
        sources.sort_by(|a, b| a.event_id.cmp(&b.event_id));
        detection_sources.sort_by_key(|source| source.report_digest);
        validate_source_inventories(&sources, &detection_sources)?;
        self.supervision_command(
            principal,
            &state.registration.session_id,
            Command::Publish {
                subscription: state.registration.subscription_id.clone(),
                expected: state.digest(),
                reservation: reservation.receipt,
                payload,
                sources,
                detection_sources,
                report_receipt,
            },
            now,
        )
    }

    /// Release exact private bytes only after live admission and durable consumption of one
    /// revalidation reservation. The deployment owner must first revalidate every source pin.
    pub fn release_supervision_payload(
        &mut self,
        principal: &PrincipalId,
        state: &SupervisionSubscription,
        reservation: &SupervisionReservation,
        receipt: ContentDigest,
        now: TimestampNs,
    ) -> Result<(SupervisionSubscription, Vec<u8>)> {
        let result = self.supervision_command(
            principal,
            &state.registration.session_id,
            Command::Release {
                subscription: state.registration.subscription_id.clone(),
                expected: state.digest(),
                reservation: reservation.receipt,
                receipt,
            },
            now,
        )?;
        let payload = result
            .pending
            .as_ref()
            .ok_or(DurableSupervisionError::Conflict)?
            .payload
            .clone();
        Ok((result, payload))
    }

    /// ACK exactly the pending delivery after current source revalidation, or confirm the exact
    /// most recent ACK retry without consuming a successor. ACK never runs the next evaluation.
    pub fn acknowledge_supervision(
        &mut self,
        principal: &PrincipalId,
        state: &SupervisionSubscription,
        reservation: Option<&SupervisionReservation>,
        receipt: ContentDigest,
        current_anchor: &LedgerAnchor,
        now: TimestampNs,
    ) -> Result<SupervisionSubscription> {
        self.supervision_command(
            principal,
            &state.registration.session_id,
            Command::Acknowledge {
                subscription: state.registration.subscription_id.clone(),
                expected: state.digest(),
                reservation: reservation.map(|r| r.receipt),
                receipt,
                anchor: current_anchor.clone(),
            },
            now,
        )
    }

    /// Explicitly invalidate one exact pending delivery without claiming it was acknowledged.
    /// This needs live authority but no source reads, so inaccessible source can be retired safely.
    pub fn discard_supervision(
        &mut self,
        principal: &PrincipalId,
        state: &SupervisionSubscription,
        receipt: ContentDigest,
        current_anchor: &LedgerAnchor,
        now: TimestampNs,
    ) -> Result<SupervisionSubscription> {
        self.supervision_command(
            principal,
            &state.registration.session_id,
            Command::Discard {
                subscription: state.registration.subscription_id.clone(),
                expected: state.digest(),
                receipt,
                anchor: current_anchor.clone(),
            },
            now,
        )
    }

    /// Activate exactly the next cumulative prefix after its current report was ACKed or
    /// explicitly discarded. Pending reports block progression; exact latest retries preserve
    /// any successor. An abandoned attempt remains charged and creates no source or effect claim.
    pub fn advance_supervision_window(
        &mut self,
        principal: &PrincipalId,
        state: &SupervisionSubscription,
        target_count: u32,
        after_receipt: ContentDigest,
        current_anchor: &LedgerAnchor,
        now: TimestampNs,
    ) -> Result<SupervisionSubscription> {
        if !(2..=MAX_SUPERVISION_WINDOWS).contains(&target_count) || !sha(after_receipt) {
            return Err(DurableSupervisionError::InvalidRequest);
        }
        self.supervision_command(
            principal,
            &state.registration.session_id,
            Command::Advance {
                subscription: state.registration.subscription_id.clone(),
                expected: state.digest(),
                target_count,
                after_receipt,
                anchor: current_anchor.clone(),
            },
            now,
        )
    }

    fn supervision_command(
        &mut self,
        principal: &PrincipalId,
        session: &SessionId,
        command: Command,
        now: TimestampNs,
    ) -> Result<SupervisionSubscription> {
        if !label(command.subscription()) {
            return Err(DurableSupervisionError::InvalidRequest);
        }
        // The existing transaction records error-side clock/expiry changes before any response.
        self.session(principal, session, now)?;
        self.preflight()?;
        let report = super::read_report(self.path(), self.limits)?;
        if report.last_root() != self.committed_root()
            || report.committed_len() != self.journal.committed_len()
            || report.incomplete_tail().is_some()
        {
            self.fenced = true;
            return Err(DurableSessionError::RootMismatch.into());
        }
        let ceilings = self.coordination.as_ref().map(|s| s.limits);
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
        let mut state = restored.supervisions;
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
        let payload = codec::encode_record(&Record {
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
            record: Some((SUPERVISION_COMMAND_RECORD_KIND, payload)),
        })?;
        Ok(result)
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

pub(super) fn replay_command(
    bytes: &[u8],
    memory: &mut ReferenceSessionStore,
    state: &mut SupervisionState,
    limits: DurableSessionLimits,
) -> std::result::Result<(), DurableSessionError> {
    let record = codec::decode_record(bytes)?;
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

#[cfg(test)]
mod schedule_tests;

#[cfg(test)]
mod compatibility_tests;

#[cfg(test)]
mod recovery_tests;

#[cfg(test)]
mod inventory_tests;

#[cfg(test)]
mod detection_tests;
