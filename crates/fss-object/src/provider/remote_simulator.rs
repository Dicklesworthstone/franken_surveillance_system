#![forbid(unsafe_code)]
//! Deterministic remote eventual-consistency and partial-list provider simulator (FSS-132).
//!
//! Models realistic S3-compatible remote object-store failure modes without network I/O or
//! external dependencies:
//! - Authoritative backend vs. lagging eventual-consistency read/list index;
//! - Paginated `list_objects` and `list_multipart_parts` with partial omissions, stale
//!   post-deletion/post-retirement ghosts, early truncation, and continuation token failures;
//! - Conditional object writes (`If-None-Match: *`, `If-Match: <etag>`), `HEAD`, and
//!   digest-verified `GET` with readback bit-flip fault injection;
//! - First-class [`ObjectStoreProvider`] (FSS-061/062) and [`MultipartTransport`] (FSS-130/063)
//!   implementations whose clean-schedule execution reproduces the exact canonical oracle digest;
//! - Bounded transition trace, operation cost row, canonical scenario digest
//!   (`fss.remote_provider_sim.v1`), and secret-free JSON-lines reporting.
//!
//! Safety rule: eventual consistency, partial listings, stale ghosts, or lost acknowledgements
//! never upgrade an uncertain/unverified observation to conclusive truth. On `reconcile`, any
//! lagging state transition or incomplete part listing reports [`ProviderUploadState::Unknown`].

pub mod faults;
pub mod listing;

use std::collections::BTreeMap;

use fss_core::{CanonicalEncoder, ContentDigest, TimestampNs};

use crate::multipart::{
    ETag, MultipartTransport, PartReceipt, ProviderUploadState, Reconciliation, TransportCx,
    TransportOperation, UploadId, UploadIntent,
};
use crate::planner::PlannedChunk;
use crate::provider::memory::InMemoryObjectStoreProvider;
use crate::provider::{
    ObjectStoreProvider, ProviderError, PublicationState, RetrievabilityWitness,
};
use crate::{InMemoryObjectStore, ObjectLimits};

pub use faults::{
    AdversarialMisbehavior, DeterministicPrng, FaultKind, FaultOperation, FaultRatesPpm, FaultRule,
    MAX_ADVERSARIAL_RULES, MAX_FAULT_RULES, MAX_FRAMING_BYTES_PER_OP, PPM_SCALE,
    REMOTE_FAULT_SCHEDULE_DOMAIN, RecoveryGuidance, RemoteFaultSchedule,
};
pub use listing::{
    ListPage, ListRequest, ListedObject, ListingCollection, ListingConsistency,
    MAX_CONTINUATION_TOKEN_BYTES, MAX_KEY_BYTES, MAX_LIST_PAGE_KEYS, MAX_LIST_PAGES_PER_COLLECT,
};

/// Canonical digest domain for remote provider simulator reports (FSS-132).
pub const REMOTE_PROVIDER_SIM_DOMAIN: &str = "fss.remote_provider_sim.v1";

/// Default ceiling on distinct tracked objects (content-addressed + key-addressed).
pub const MAX_SIMULATOR_OBJECTS: usize = 4_096;

/// Default ceiling on total retained payload bytes inside the simulator (128 MiB).
pub const MAX_SIMULATOR_BYTES: u64 = 128 * 1024 * 1024;

/// Default ceiling on tracked multipart uploads.
pub const MAX_SIMULATOR_UPLOADS: usize = 256;

/// Default ceiling on retained structured trace records.
pub const MAX_TRACE_ENTRIES: usize = 4_096;

/// Hard resource limits enforced by [`RemoteProviderSimulator`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SimulatorLimits {
    /// Maximum objects stored simultaneously.
    pub max_objects: usize,
    /// Maximum total retained bytes across stored payloads.
    pub max_bytes: u64,
    /// Maximum distinct multipart upload intents tracked.
    pub max_uploads: usize,
    /// Maximum entries returned in one list page.
    pub max_list_page_keys: usize,
    /// Maximum trace records retained before marking `trace_truncated`.
    pub max_trace_entries: usize,
    /// Required replica count reported by the underlying provider lattice.
    pub required_replicas: u32,
}

impl Default for SimulatorLimits {
    fn default() -> Self {
        Self {
            max_objects: MAX_SIMULATOR_OBJECTS,
            max_bytes: MAX_SIMULATOR_BYTES,
            max_uploads: MAX_SIMULATOR_UPLOADS,
            max_list_page_keys: MAX_LIST_PAGE_KEYS,
            max_trace_entries: MAX_TRACE_ENTRIES,
            required_replicas: 2,
        }
    }
}

impl SimulatorLimits {
    /// Validates every limit is strictly positive and within hard upper bounds.
    pub fn validate(&self) -> Result<(), RemoteObjectError> {
        if self.max_objects == 0 || self.max_objects > MAX_SIMULATOR_OBJECTS {
            return Err(RemoteObjectError::InvalidRequest(format!(
                "max_objects ({}) must be within 1..={MAX_SIMULATOR_OBJECTS}",
                self.max_objects
            )));
        }
        if self.max_bytes == 0 || self.max_bytes > MAX_SIMULATOR_BYTES {
            return Err(RemoteObjectError::InvalidRequest(format!(
                "max_bytes ({}) must be within 1..={MAX_SIMULATOR_BYTES}",
                self.max_bytes
            )));
        }
        if self.max_uploads == 0 || self.max_uploads > MAX_SIMULATOR_UPLOADS {
            return Err(RemoteObjectError::InvalidRequest(format!(
                "max_uploads ({}) must be within 1..={MAX_SIMULATOR_UPLOADS}",
                self.max_uploads
            )));
        }
        if self.max_list_page_keys == 0 || self.max_list_page_keys > MAX_LIST_PAGE_KEYS {
            return Err(RemoteObjectError::InvalidRequest(format!(
                "max_list_page_keys ({}) must be within 1..={MAX_LIST_PAGE_KEYS}",
                self.max_list_page_keys
            )));
        }
        if self.max_trace_entries == 0 || self.max_trace_entries > MAX_TRACE_ENTRIES {
            return Err(RemoteObjectError::InvalidRequest(format!(
                "max_trace_entries ({}) must be within 1..={MAX_TRACE_ENTRIES}",
                self.max_trace_entries
            )));
        }
        if self.required_replicas == 0 {
            return Err(RemoteObjectError::InvalidRequest(
                "required_replicas must be >= 1".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Conditional precondition on key-addressed remote writes/deletes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConditionalPrecondition {
    /// No conditional header supplied.
    None,
    /// `If-None-Match: *` — succeed only if the key does not currently hold a live object.
    IfNoneMatchAny,
    /// `If-Match: <etag>` — succeed only if the current live object has this exact ETag.
    IfMatch(ETag),
}

/// Metadata returned by `put_object_conditional` and `head_object`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteObjectHead {
    /// Object key.
    pub key: String,
    /// Verified SHA-256 content digest.
    pub digest: ContentDigest,
    /// Opaque provider ETag (distinct from content digest).
    pub etag: ETag,
    /// Exact payload length in bytes.
    pub size_bytes: u64,
    /// Authoritative commit epoch of this revision.
    pub commit_epoch: u64,
}

/// Typed refusal returned by key-addressed, listing, and simulator setup calls.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemoteObjectError {
    /// Malformed request, key, schedule, or limit.
    InvalidRequest(String),
    /// Object key or upload intent does not exist.
    NotFound {
        /// Missing target identifier.
        target: String,
    },
    /// Authoritative mutation committed but is not yet visible at the current epoch.
    EventualLagUnavailable {
        /// Key or digest lagging behind visibility.
        target: String,
        /// Epoch at which the mutation becomes visible.
        visible_at_epoch: u64,
        /// Current simulator logical epoch.
        current_epoch: u64,
    },
    /// `If-None-Match` or `If-Match` precondition failed against authoritative state.
    PreconditionFailed {
        /// Target key.
        key: String,
        /// Machine-readable reason.
        reason: String,
    },
    /// Readback bytes failed SHA-256 verification against the committed content digest.
    DigestMismatch {
        /// Expected committed content digest.
        expected: ContentDigest,
        /// Observed corrupted readback digest.
        observed: ContentDigest,
    },
    /// Mutation committed on the backend, then acknowledgement dropped (outcome uncertain).
    LostAcknowledgement {
        /// Operation whose acknowledgement was dropped.
        operation: FaultOperation,
        /// Target key or digest label.
        target: String,
    },
    /// Transient transport/provider failure before committing any effect.
    TransientUnavailable {
        /// Operation refused before effect.
        operation: FaultOperation,
        /// Machine-readable reason.
        detail: String,
    },
    /// Rate-limit / service backpressure (429/503) before effect.
    RateLimited {
        /// Operation throttled.
        operation: FaultOperation,
    },
    /// Object-count, byte-capacity, or upload-count limit exceeded.
    QuotaExceeded {
        /// Resource ceiling hit.
        detail: String,
    },
    /// Continuation token rejected (expired, tampered, or fault-injected).
    CorruptContinuationToken {
        /// Validation failure detail.
        detail: String,
    },
}

impl RemoteObjectError {
    /// Safe typed recovery guidance for this refusal.
    #[must_use]
    pub const fn recovery_guidance(&self) -> RecoveryGuidance {
        match self {
            Self::InvalidRequest(_) => RecoveryGuidance::FixRequestOrAuthority,
            Self::NotFound { .. } => RecoveryGuidance::RevalidateConditionalPrecondition,
            Self::EventualLagUnavailable { .. } => RecoveryGuidance::WaitVisibilityAndRetry,
            Self::PreconditionFailed { .. } => RecoveryGuidance::RevalidateConditionalPrecondition,
            Self::DigestMismatch { .. } => RecoveryGuidance::QuarantineAndRepairFromManifest,
            Self::LostAcknowledgement { .. } => RecoveryGuidance::ReconcileBeforeRetry,
            Self::TransientUnavailable { .. } => RecoveryGuidance::RetrySameIntent,
            Self::RateLimited { .. } | Self::QuotaExceeded { .. } => {
                RecoveryGuidance::BackoffOrSettleIndeterminate
            }
            Self::CorruptContinuationToken { .. } => RecoveryGuidance::ResetPaginationFromStart,
        }
    }

    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::NotFound { .. } => "not_found",
            Self::EventualLagUnavailable { .. } => "eventual_lag_unavailable",
            Self::PreconditionFailed { .. } => "precondition_failed",
            Self::DigestMismatch { .. } => "digest_mismatch",
            Self::LostAcknowledgement { .. } => "lost_acknowledgement",
            Self::TransientUnavailable { .. } => "transient_unavailable",
            Self::RateLimited { .. } => "rate_limited",
            Self::QuotaExceeded { .. } => "quota_exceeded",
            Self::CorruptContinuationToken { .. } => "corrupt_continuation_token",
        }
    }
}

impl std::fmt::Display for RemoteObjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(d) => write!(f, "invalid remote simulator request: {d}"),
            Self::NotFound { target } => write!(f, "remote target not found: {target}"),
            Self::EventualLagUnavailable {
                target,
                visible_at_epoch,
                current_epoch,
            } => write!(
                f,
                "remote target {target} unavailable due to eventual visibility lag (epoch {current_epoch} < visible_at {visible_at_epoch})"
            ),
            Self::PreconditionFailed { key, reason } => {
                write!(f, "conditional precondition failed for {key}: {reason}")
            }
            Self::DigestMismatch { expected, observed } => {
                write!(
                    f,
                    "readback digest mismatch: expected {expected}, observed {observed}"
                )
            }
            Self::LostAcknowledgement { operation, target } => {
                write!(
                    f,
                    "lost acknowledgement after {} on {target}; reconcile before retry",
                    operation.as_str()
                )
            }
            Self::TransientUnavailable { operation, detail } => {
                write!(
                    f,
                    "transient failure before {}: {detail}",
                    operation.as_str()
                )
            }
            Self::RateLimited { operation } => {
                write!(f, "rate limited before {}", operation.as_str())
            }
            Self::QuotaExceeded { detail } => write!(f, "remote quota exceeded: {detail}"),
            Self::CorruptContinuationToken { detail } => {
                write!(f, "corrupt continuation token: {detail}")
            }
        }
    }
}

impl std::error::Error for RemoteObjectError {}

/// Operation-cost accounting row for one simulator run (FSS-132).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SimulatorCostRow {
    /// Total `ObjectStoreProvider` stage/advance/root/retire/verify/state operations.
    pub provider_ops: u64,
    /// Total multipart initiate calls.
    pub initiate_ops: u64,
    /// Total multipart upload_part calls.
    pub upload_part_ops: u64,
    /// Total multipart complete calls.
    pub complete_ops: u64,
    /// Total multipart abort calls.
    pub abort_ops: u64,
    /// Total multipart reconcile calls.
    pub reconcile_ops: u64,
    /// Total object and multipart-part list calls.
    pub list_ops: u64,
    /// Total conditional put/head/get/delete object calls.
    pub keyspace_ops: u64,
    /// Total payload + framing bytes received by the simulator.
    pub wire_bytes_in: u64,
    /// Total payload + framing bytes emitted by the simulator.
    pub wire_bytes_out: u64,
    /// Total faults injected across all operations.
    pub faults_injected: u64,
    /// Total `ProviderUploadState::Unknown` observations emitted on reconciliation.
    pub unknown_reconciliations: u64,
    /// Total readback digest mismatches caught before returning bytes or witnesses.
    pub corruptions_caught: u64,
}

impl SimulatorCostRow {
    fn encode_canonical(&self, enc: &mut CanonicalEncoder) {
        enc.u64(self.provider_ops);
        enc.u64(self.initiate_ops);
        enc.u64(self.upload_part_ops);
        enc.u64(self.complete_ops);
        enc.u64(self.abort_ops);
        enc.u64(self.reconcile_ops);
        enc.u64(self.list_ops);
        enc.u64(self.keyspace_ops);
        enc.u64(self.wire_bytes_in);
        enc.u64(self.wire_bytes_out);
        enc.u64(self.faults_injected);
        enc.u64(self.unknown_reconciliations);
        enc.u64(self.corruptions_caught);
    }
}

/// Bounded secret-free trace record of one simulated operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulatorTraceEntry {
    /// Monotonic 1-based trace sequence number.
    pub seq: u64,
    /// Authoritative logical epoch when the call executed.
    pub epoch: u64,
    /// Operation executed.
    pub operation: FaultOperation,
    /// Stable target identity (digest text or bounded key, never raw media or secrets).
    pub target: String,
    /// Injected fault label, if any.
    pub fault: Option<&'static str>,
    /// Machine-readable outcome (`"ok"`, `"unknown"`, or typed error code).
    pub outcome: String,
    /// Wire bytes transferred by this call.
    pub wire_bytes: u64,
}

impl SimulatorTraceEntry {
    fn encode_canonical(&self, enc: &mut CanonicalEncoder) {
        enc.u64(self.seq);
        enc.u64(self.epoch);
        enc.u8(self.operation.tag());
        enc.text(&self.target);
        enc.bool(self.fault.is_some());
        if let Some(f) = self.fault {
            enc.text(f);
        }
        enc.text(&self.outcome);
        enc.u64(self.wire_bytes);
    }
}

/// Canonical summary report emitted by [`RemoteProviderSimulator::report`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulatorReport {
    /// PRNG seed used by the simulator.
    pub seed: u64,
    /// Canonical digest of the exact [`RemoteFaultSchedule`].
    pub schedule_digest: ContentDigest,
    /// Final authoritative logical epoch.
    pub authoritative_epoch: u64,
    /// Total trace entries retained (bounded by `max_trace_entries`).
    pub trace_count: usize,
    /// True if trace entries exceeded the retention cap and newer entries were omitted.
    pub trace_truncated: bool,
    /// Accumulated operation and byte costs.
    pub cost: SimulatorCostRow,
    /// Count of active (unsettled) multipart uploads in authoritative backend state.
    pub active_uploads: usize,
    /// Count of completed multipart uploads in authoritative backend state.
    pub completed_uploads: usize,
    /// Count of aborted multipart uploads in authoritative backend state.
    pub aborted_uploads: usize,
    /// Count of tracked objects across provider and keyspace tables.
    pub tracked_objects: usize,
    /// Count of post-delete/retire ghost entries currently lingering in list views.
    pub ghost_entries: usize,
    /// Canonical digest over seed, schedule, costs, final states, and trace.
    pub scenario_digest: ContentDigest,
}

impl SimulatorReport {
    /// Emits a bounded, secret-free JSON-lines record suitable for E2E harnesses and proof bundles.
    #[must_use]
    pub fn to_jsonl_line(&self, scenario: &str, repro_cmd: &str) -> String {
        format!(
            concat!(
                "{{\"schema\":\"{}\",\"scenario\":\"{}\",\"seed\":{},",
                "\"schedule_digest\":\"{}\",\"authoritative_epoch\":{},",
                "\"trace_count\":{},\"trace_truncated\":{},",
                "\"cost\":{{\"provider_ops\":{},\"initiate_ops\":{},\"upload_part_ops\":{},",
                "\"complete_ops\":{},\"abort_ops\":{},\"reconcile_ops\":{},\"list_ops\":{},",
                "\"keyspace_ops\":{},\"wire_bytes_in\":{},\"wire_bytes_out\":{},",
                "\"faults_injected\":{},\"unknown_reconciliations\":{},\"corruptions_caught\":{}}},",
                "\"uploads\":{{\"active\":{},\"completed\":{},\"aborted\":{}}},",
                "\"tracked_objects\":{},\"ghost_entries\":{},",
                "\"scenario_digest\":\"{}\",\"repro\":\"{}\"}}"
            ),
            REMOTE_PROVIDER_SIM_DOMAIN,
            json_escape(scenario),
            self.seed,
            self.schedule_digest,
            self.authoritative_epoch,
            self.trace_count,
            self.trace_truncated,
            self.cost.provider_ops,
            self.cost.initiate_ops,
            self.cost.upload_part_ops,
            self.cost.complete_ops,
            self.cost.abort_ops,
            self.cost.reconcile_ops,
            self.cost.list_ops,
            self.cost.keyspace_ops,
            self.cost.wire_bytes_in,
            self.cost.wire_bytes_out,
            self.cost.faults_injected,
            self.cost.unknown_reconciliations,
            self.cost.corruptions_caught,
            self.active_uploads,
            self.completed_uploads,
            self.aborted_uploads,
            self.tracked_objects,
            self.ghost_entries,
            self.scenario_digest,
            json_escape(repro_cmd),
        )
    }
}

fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

#[derive(Clone, Debug)]
struct ProviderObjectMeta {
    key: String,
    etag: ETag,
    size_bytes: u64,
    state: PublicationState,
    commit_epoch: u64,
    visible_at_epoch: u64,
    retired_at_epoch: Option<u64>,
}

#[derive(Clone, Debug)]
struct KeyspaceObject {
    digest: ContentDigest,
    etag: ETag,
    bytes: Vec<u8>,
    size_bytes: u64,
    commit_epoch: u64,
    visible_at_epoch: u64,
    deleted_at_epoch: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemoteUploadPhase {
    Active,
    Completed,
    Aborted,
}

impl RemoteUploadPhase {
    const fn tag(self) -> u8 {
        match self {
            Self::Active => 1,
            Self::Completed => 2,
            Self::Aborted => 3,
        }
    }
}

#[derive(Clone, Debug)]
struct SimulatedPart {
    receipt: PartReceipt,
    commit_epoch: u64,
    visible_at_epoch: u64,
    len: u64,
}

#[derive(Clone, Debug)]
struct SimulatedUpload {
    upload_id: UploadId,
    intent: UploadIntent,
    phase: RemoteUploadPhase,
    commit_epoch: u64,
    visible_at_epoch: u64,
    parts: BTreeMap<u64, SimulatedPart>,
    complete_dispatched: bool,
}

/// Deterministic remote object-store & multipart simulator with eventual consistency and
/// partial-list fault injection (FSS-132).
#[derive(Debug)]
pub struct RemoteProviderSimulator {
    limits: SimulatorLimits,
    schedule: RemoteFaultSchedule,
    prng: DeterministicPrng,
    epoch: u64,
    next_etag_seq: u64,
    next_upload_seq: u64,
    trace_seq: u64,
    op_counts: BTreeMap<FaultOperation, u64>,
    remaining_adversarial: Vec<AdversarialMisbehavior>,
    inner: InMemoryObjectStoreProvider,
    provider_meta: BTreeMap<ContentDigest, ProviderObjectMeta>,
    keyspace: BTreeMap<String, KeyspaceObject>,
    keyspace_live_bytes: u64,
    uploads: BTreeMap<ContentDigest, SimulatedUpload>,
    upload_id_to_intent: BTreeMap<UploadId, ContentDigest>,
    cost: SimulatorCostRow,
    trace: Vec<SimulatorTraceEntry>,
    trace_truncated: bool,
}

impl RemoteProviderSimulator {
    /// Creates a new simulator enforcing `limits` and `schedule`.
    pub fn new(
        limits: SimulatorLimits,
        schedule: RemoteFaultSchedule,
    ) -> Result<Self, RemoteObjectError> {
        limits.validate()?;
        schedule
            .validate()
            .map_err(RemoteObjectError::InvalidRequest)?;
        let custody_limits = ObjectLimits::new(limits.max_objects, limits.max_bytes);
        let inner = InMemoryObjectStoreProvider::new(
            InMemoryObjectStore::new(custody_limits),
            limits.required_replicas,
        );
        let prng = DeterministicPrng::new(schedule.seed);
        let remaining_adversarial = schedule.adversarial.clone();
        Ok(Self {
            limits,
            schedule,
            prng,
            epoch: 0,
            next_etag_seq: 0,
            next_upload_seq: 0,
            trace_seq: 0,
            op_counts: BTreeMap::new(),
            remaining_adversarial,
            inner,
            provider_meta: BTreeMap::new(),
            keyspace: BTreeMap::new(),
            keyspace_live_bytes: 0,
            uploads: BTreeMap::new(),
            upload_id_to_intent: BTreeMap::new(),
            cost: SimulatorCostRow::default(),
            trace: Vec::new(),
            trace_truncated: false,
        })
    }

    /// Creates a zero-fault, zero-lag simulator with default limits for reference parity.
    pub fn clean(seed: u64) -> Result<Self, RemoteObjectError> {
        Self::new(SimulatorLimits::default(), RemoteFaultSchedule::clean(seed))
    }

    /// Current authoritative logical epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Advances the simulator's logical clock by `steps`, allowing lagging writes to catch up
    /// and expiring aged post-deletion ghost entries.
    pub fn advance_epoch(&mut self, steps: u64) {
        self.epoch = self.epoch.saturating_add(steps);
    }

    /// Advances the logical epoch far enough that every currently committed mutation is visible
    /// and every currently pending ghost entry has expired.
    pub fn flush_visibility(&mut self) {
        let mut target = self.epoch;
        for meta in self.provider_meta.values() {
            target = target.max(meta.visible_at_epoch);
            if let Some(retired) = meta.retired_at_epoch {
                target = target.max(retired.saturating_add(self.schedule.ghost_retention_steps));
            }
        }
        for obj in self.keyspace.values() {
            target = target.max(obj.visible_at_epoch);
            if let Some(deleted) = obj.deleted_at_epoch {
                target = target.max(deleted.saturating_add(self.schedule.ghost_retention_steps));
            }
        }
        for upload in self.uploads.values() {
            target = target.max(upload.visible_at_epoch);
            for part in upload.parts.values() {
                target = target.max(part.visible_at_epoch);
            }
        }
        self.epoch = target;
    }

    /// Returns retained structured trace records.
    #[must_use]
    pub fn trace(&self) -> &[SimulatorTraceEntry] {
        &self.trace
    }

    /// Returns accumulated operation and wire-byte costs.
    #[must_use]
    pub const fn cost(&self) -> SimulatorCostRow {
        self.cost
    }

    /// Returns the immutable fault schedule bound to this simulator.
    #[must_use]
    pub const fn schedule(&self) -> &RemoteFaultSchedule {
        &self.schedule
    }

    /// Builds a canonical deterministic summary report with digest (`fss.remote_provider_sim.v1`).
    #[must_use]
    pub fn report(&self) -> SimulatorReport {
        let schedule_digest = self.schedule.digest();
        let active_uploads = self
            .uploads
            .values()
            .filter(|u| u.phase == RemoteUploadPhase::Active)
            .count();
        let completed_uploads = self
            .uploads
            .values()
            .filter(|u| u.phase == RemoteUploadPhase::Completed)
            .count();
        let aborted_uploads = self
            .uploads
            .values()
            .filter(|u| u.phase == RemoteUploadPhase::Aborted)
            .count();
        let ghost_entries = self.count_active_ghosts();
        let tracked_objects = self.provider_meta.len() + self.keyspace.len();

        let mut enc = CanonicalEncoder::new();
        enc.text(REMOTE_PROVIDER_SIM_DOMAIN);
        enc.u64(self.schedule.seed);
        enc.digest(schedule_digest);
        enc.u64(self.epoch);
        enc.u64(self.trace.len() as u64);
        enc.bool(self.trace_truncated);
        self.cost.encode_canonical(&mut enc);

        enc.u64(self.provider_meta.len() as u64);
        for (digest, meta) in &self.provider_meta {
            enc.digest(*digest);
            enc.text(meta.state.as_str());
            enc.u64(meta.commit_epoch);
            enc.u64(meta.visible_at_epoch);
        }

        enc.u64(self.keyspace.len() as u64);
        for (key, obj) in &self.keyspace {
            enc.text(key);
            enc.digest(obj.digest);
            enc.bool(obj.deleted_at_epoch.is_some());
            enc.u64(obj.commit_epoch);
            enc.u64(obj.visible_at_epoch);
        }

        enc.u64(self.uploads.len() as u64);
        for (intent_digest, upload) in &self.uploads {
            enc.digest(*intent_digest);
            enc.text(&upload.upload_id.0);
            enc.u8(upload.phase.tag());
            enc.u64(upload.parts.len() as u64);
            for (idx, part) in &upload.parts {
                enc.u64(*idx);
                enc.digest(part.receipt.content_digest);
                enc.text(&part.receipt.etag.0);
                enc.u64(part.commit_epoch);
                enc.u64(part.visible_at_epoch);
                enc.u64(part.len);
            }
        }

        enc.u64(self.trace.len() as u64);
        for entry in &self.trace {
            entry.encode_canonical(&mut enc);
        }

        SimulatorReport {
            seed: self.schedule.seed,
            schedule_digest,
            authoritative_epoch: self.epoch,
            trace_count: self.trace.len(),
            trace_truncated: self.trace_truncated,
            cost: self.cost,
            active_uploads,
            completed_uploads,
            aborted_uploads,
            tracked_objects,
            ghost_entries,
            scenario_digest: ContentDigest::sha256(&enc.finish()),
        }
    }

    // ---- Key-addressed conditional object protocol -----------------------

    /// Writes `bytes` under `key` enforcing `precondition` (`If-None-Match: *` / `If-Match`).
    pub fn put_object_conditional(
        &mut self,
        key: &str,
        bytes: &[u8],
        precondition: ConditionalPrecondition,
    ) -> Result<RemoteObjectHead, RemoteObjectError> {
        self.cost.keyspace_ops = self.cost.keyspace_ops.saturating_add(1);
        validate_key(key)?;
        let digest = ContentDigest::sha256(bytes);
        let ordinal = self.bump_op(FaultOperation::PutConditional);
        let fault = self.select_fault(FaultOperation::PutConditional, ordinal, Some(digest));
        let wire_in = (bytes.len() as u64).saturating_add(self.schedule.framing_bytes_per_op);

        match fault {
            Some(FaultKind::FailBeforeEffect) => {
                self.record_fault(
                    FaultOperation::PutConditional,
                    key,
                    FaultKind::FailBeforeEffect,
                    "transient_unavailable",
                    self.schedule.framing_bytes_per_op,
                );
                return Err(RemoteObjectError::TransientUnavailable {
                    operation: FaultOperation::PutConditional,
                    detail: "injected pre-effect outage".to_owned(),
                });
            }
            Some(FaultKind::ThrottleRateLimit) => {
                self.record_fault(
                    FaultOperation::PutConditional,
                    key,
                    FaultKind::ThrottleRateLimit,
                    "rate_limited",
                    self.schedule.framing_bytes_per_op,
                );
                return Err(RemoteObjectError::RateLimited {
                    operation: FaultOperation::PutConditional,
                });
            }
            Some(FaultKind::QuotaExceeded) => {
                self.record_fault(
                    FaultOperation::PutConditional,
                    key,
                    FaultKind::QuotaExceeded,
                    "quota_exceeded",
                    self.schedule.framing_bytes_per_op,
                );
                return Err(RemoteObjectError::QuotaExceeded {
                    detail: "injected remote byte/object quota ceiling".to_owned(),
                });
            }
            _ => {}
        }

        // Evaluate conditional precondition against authoritative key state.
        let existing_live = self
            .keyspace
            .get(key)
            .filter(|entry| entry.deleted_at_epoch.is_none());
        match &precondition {
            ConditionalPrecondition::None => {}
            ConditionalPrecondition::IfNoneMatchAny => {
                if existing_live.is_some() {
                    self.record_trace(
                        FaultOperation::PutConditional,
                        key,
                        None,
                        "precondition_failed",
                        self.schedule.framing_bytes_per_op,
                    );
                    return Err(RemoteObjectError::PreconditionFailed {
                        key: key.to_owned(),
                        reason: "If-None-Match '*' refused: key already exists".to_owned(),
                    });
                }
            }
            ConditionalPrecondition::IfMatch(expected) => match existing_live {
                Some(entry) if entry.etag == *expected => {}
                Some(_) => {
                    self.record_trace(
                        FaultOperation::PutConditional,
                        key,
                        None,
                        "precondition_failed",
                        self.schedule.framing_bytes_per_op,
                    );
                    return Err(RemoteObjectError::PreconditionFailed {
                        key: key.to_owned(),
                        reason: "If-Match ETag mismatch".to_owned(),
                    });
                }
                None => {
                    self.record_trace(
                        FaultOperation::PutConditional,
                        key,
                        None,
                        "precondition_failed",
                        self.schedule.framing_bytes_per_op,
                    );
                    return Err(RemoteObjectError::PreconditionFailed {
                        key: key.to_owned(),
                        reason: "If-Match refused: key does not exist".to_owned(),
                    });
                }
            },
        }

        // Check hard limits before mutating state.
        let replaced_bytes = existing_live.map_or(0, |e| e.size_bytes);
        let live_object_count = self
            .keyspace
            .values()
            .filter(|e| e.deleted_at_epoch.is_none())
            .count();
        let adding_new_live = existing_live.is_none();
        if adding_new_live
            && live_object_count + self.provider_meta.len() >= self.limits.max_objects
        {
            self.record_trace(
                FaultOperation::PutConditional,
                key,
                None,
                "quota_exceeded",
                0,
            );
            return Err(RemoteObjectError::QuotaExceeded {
                detail: format!("object limit {} reached", self.limits.max_objects),
            });
        }
        let next_bytes = self
            .keyspace_live_bytes
            .saturating_sub(replaced_bytes)
            .saturating_add(bytes.len() as u64);
        if next_bytes > self.limits.max_bytes {
            self.record_trace(
                FaultOperation::PutConditional,
                key,
                None,
                "quota_exceeded",
                0,
            );
            return Err(RemoteObjectError::QuotaExceeded {
                detail: format!(
                    "byte limit {} exceeded by write of {} bytes",
                    self.limits.max_bytes,
                    bytes.len()
                ),
            });
        }

        let lag = match fault {
            Some(FaultKind::EventualVisibilityLag { lag_steps }) => lag_steps,
            _ => self.schedule.default_visibility_lag,
        };
        let etag = self.mint_etag("obj");
        let commit_epoch = self.epoch;
        let visible_at_epoch = commit_epoch.saturating_add(lag);
        self.keyspace_live_bytes = next_bytes;
        self.keyspace.insert(
            key.to_owned(),
            KeyspaceObject {
                digest,
                etag: etag.clone(),
                bytes: bytes.to_vec(),
                size_bytes: bytes.len() as u64,
                commit_epoch,
                visible_at_epoch,
                deleted_at_epoch: None,
            },
        );
        self.cost.wire_bytes_in = self.cost.wire_bytes_in.saturating_add(wire_in);

        if matches!(fault, Some(FaultKind::LostAckAfterEffect)) {
            self.record_fault(
                FaultOperation::PutConditional,
                key,
                FaultKind::LostAckAfterEffect,
                "lost_acknowledgement",
                wire_in,
            );
            return Err(RemoteObjectError::LostAcknowledgement {
                operation: FaultOperation::PutConditional,
                target: key.to_owned(),
            });
        }

        let injected = match fault {
            Some(FaultKind::EventualVisibilityLag { .. }) => {
                self.cost.faults_injected = self.cost.faults_injected.saturating_add(1);
                Some(FaultKind::EventualVisibilityLag { lag_steps: lag }.as_str())
            }
            _ => None,
        };
        self.record_trace(FaultOperation::PutConditional, key, injected, "ok", wire_in);
        Ok(RemoteObjectHead {
            key: key.to_owned(),
            digest,
            etag,
            size_bytes: bytes.len() as u64,
            commit_epoch,
        })
    }

    /// Reads object metadata respecting eventual visibility lag.
    pub fn head_object(&mut self, key: &str) -> Result<RemoteObjectHead, RemoteObjectError> {
        self.cost.keyspace_ops = self.cost.keyspace_ops.saturating_add(1);
        validate_key(key)?;
        let ordinal = self.bump_op(FaultOperation::HeadObject);
        let target_digest = self.keyspace.get(key).map(|o| o.digest);
        let fault = self.select_fault(FaultOperation::HeadObject, ordinal, target_digest);
        self.check_pre_effect_fault(FaultOperation::HeadObject, key, fault)?;

        let Some(entry) = self.keyspace.get(key) else {
            self.record_trace(FaultOperation::HeadObject, key, None, "not_found", 0);
            return Err(RemoteObjectError::NotFound {
                target: key.to_owned(),
            });
        };
        if entry.deleted_at_epoch.is_some() {
            self.record_trace(FaultOperation::HeadObject, key, None, "not_found", 0);
            return Err(RemoteObjectError::NotFound {
                target: key.to_owned(),
            });
        }
        if entry.visible_at_epoch > self.epoch {
            let vis = entry.visible_at_epoch;
            self.record_trace(
                FaultOperation::HeadObject,
                key,
                Some("eventual_visibility_lag"),
                "eventual_lag_unavailable",
                0,
            );
            return Err(RemoteObjectError::EventualLagUnavailable {
                target: key.to_owned(),
                visible_at_epoch: vis,
                current_epoch: self.epoch,
            });
        }
        let head = RemoteObjectHead {
            key: key.to_owned(),
            digest: entry.digest,
            etag: entry.etag.clone(),
            size_bytes: entry.size_bytes,
            commit_epoch: entry.commit_epoch,
        };
        self.cost.wire_bytes_out = self
            .cost
            .wire_bytes_out
            .saturating_add(self.schedule.framing_bytes_per_op);
        self.record_trace(
            FaultOperation::HeadObject,
            key,
            None,
            "ok",
            self.schedule.framing_bytes_per_op,
        );
        Ok(head)
    }

    /// Reads and independently re-hashes object bytes; corrupted readbacks refuse with
    /// [`RemoteObjectError::DigestMismatch`].
    pub fn get_object_verified(
        &mut self,
        key: &str,
    ) -> Result<(RemoteObjectHead, Vec<u8>), RemoteObjectError> {
        self.cost.keyspace_ops = self.cost.keyspace_ops.saturating_add(1);
        validate_key(key)?;
        let ordinal = self.bump_op(FaultOperation::GetObject);
        let target_digest = self.keyspace.get(key).map(|o| o.digest);
        let fault = self.select_fault(FaultOperation::GetObject, ordinal, target_digest);
        self.check_pre_effect_fault(FaultOperation::GetObject, key, fault)?;

        let Some(entry) = self.keyspace.get(key) else {
            self.record_trace(FaultOperation::GetObject, key, None, "not_found", 0);
            return Err(RemoteObjectError::NotFound {
                target: key.to_owned(),
            });
        };
        if entry.deleted_at_epoch.is_some() {
            self.record_trace(FaultOperation::GetObject, key, None, "not_found", 0);
            return Err(RemoteObjectError::NotFound {
                target: key.to_owned(),
            });
        }
        if entry.visible_at_epoch > self.epoch {
            let vis = entry.visible_at_epoch;
            self.record_trace(
                FaultOperation::GetObject,
                key,
                Some("eventual_visibility_lag"),
                "eventual_lag_unavailable",
                0,
            );
            return Err(RemoteObjectError::EventualLagUnavailable {
                target: key.to_owned(),
                visible_at_epoch: vis,
                current_epoch: self.epoch,
            });
        }
        let expected = entry.digest;
        let head = RemoteObjectHead {
            key: key.to_owned(),
            digest: expected,
            etag: entry.etag.clone(),
            size_bytes: entry.size_bytes,
            commit_epoch: entry.commit_epoch,
        };
        let mut bytes = entry.bytes.clone();
        let wire_out = (bytes.len() as u64).saturating_add(self.schedule.framing_bytes_per_op);
        self.cost.wire_bytes_out = self.cost.wire_bytes_out.saturating_add(wire_out);

        if matches!(fault, Some(FaultKind::CorruptReadback)) {
            if let Some(first) = bytes.first_mut() {
                *first ^= 0x01;
            } else {
                bytes.push(0xff);
            }
            let observed = ContentDigest::sha256(&bytes);
            self.cost.corruptions_caught = self.cost.corruptions_caught.saturating_add(1);
            self.record_fault(
                FaultOperation::GetObject,
                key,
                FaultKind::CorruptReadback,
                "digest_mismatch",
                wire_out,
            );
            return Err(RemoteObjectError::DigestMismatch { expected, observed });
        }

        let observed = ContentDigest::sha256(&bytes);
        if observed != expected {
            self.cost.corruptions_caught = self.cost.corruptions_caught.saturating_add(1);
            self.record_trace(
                FaultOperation::GetObject,
                key,
                None,
                "digest_mismatch",
                wire_out,
            );
            return Err(RemoteObjectError::DigestMismatch { expected, observed });
        }

        self.record_trace(FaultOperation::GetObject, key, None, "ok", wire_out);
        Ok((head, bytes))
    }

    /// Deletes a key-addressed object with optional `If-Match` check. When
    /// `ghost_retention_steps > 0`, the deleted key lingers as a stale ghost in `list_objects`
    /// while `head_object` / `get_object_verified` immediately report `NotFound`.
    pub fn delete_object_key(
        &mut self,
        key: &str,
        precondition: ConditionalPrecondition,
    ) -> Result<(), RemoteObjectError> {
        self.cost.keyspace_ops = self.cost.keyspace_ops.saturating_add(1);
        validate_key(key)?;
        let ordinal = self.bump_op(FaultOperation::DeleteObject);
        let target_digest = self.keyspace.get(key).map(|o| o.digest);
        let fault = self.select_fault(FaultOperation::DeleteObject, ordinal, target_digest);
        self.check_pre_effect_fault(FaultOperation::DeleteObject, key, fault)?;

        let Some(entry) = self.keyspace.get_mut(key) else {
            self.record_trace(FaultOperation::DeleteObject, key, None, "not_found", 0);
            return Err(RemoteObjectError::NotFound {
                target: key.to_owned(),
            });
        };
        if entry.deleted_at_epoch.is_some() {
            self.record_trace(FaultOperation::DeleteObject, key, None, "not_found", 0);
            return Err(RemoteObjectError::NotFound {
                target: key.to_owned(),
            });
        }
        if let ConditionalPrecondition::IfMatch(expected) = precondition
            && entry.etag != expected
        {
            self.record_trace(
                FaultOperation::DeleteObject,
                key,
                None,
                "precondition_failed",
                0,
            );
            return Err(RemoteObjectError::PreconditionFailed {
                key: key.to_owned(),
                reason: "If-Match ETag mismatch on delete".to_owned(),
            });
        }
        let freed = entry.size_bytes;
        entry.bytes.clear();
        entry.deleted_at_epoch = Some(self.epoch);
        self.keyspace_live_bytes = self.keyspace_live_bytes.saturating_sub(freed);

        if matches!(fault, Some(FaultKind::LostAckAfterEffect)) {
            self.record_fault(
                FaultOperation::DeleteObject,
                key,
                FaultKind::LostAckAfterEffect,
                "lost_acknowledgement",
                self.schedule.framing_bytes_per_op,
            );
            return Err(RemoteObjectError::LostAcknowledgement {
                operation: FaultOperation::DeleteObject,
                target: key.to_owned(),
            });
        }
        self.record_trace(
            FaultOperation::DeleteObject,
            key,
            None,
            "ok",
            self.schedule.framing_bytes_per_op,
        );
        Ok(())
    }

    // ---- Paginated object & multipart part listings ----------------------

    /// Lists visible objects across both key-addressed and content-addressed provider tables,
    /// exposing eventual-visibility lag, stale post-delete ghosts, partial omissions, and
    /// bounded continuation pagination.
    pub fn list_objects(
        &mut self,
        request: &ListRequest,
    ) -> Result<ListPage<ListedObject>, RemoteObjectError> {
        self.cost.list_ops = self.cost.list_ops.saturating_add(1);
        request
            .validate(self.limits.max_list_page_keys)
            .map_err(RemoteObjectError::InvalidRequest)?;
        let ordinal = self.bump_op(FaultOperation::ListObjects);
        let fault = self.select_fault(FaultOperation::ListObjects, ordinal, None);
        let prefix_label = request.prefix.as_deref().unwrap_or("*");

        if matches!(fault, Some(FaultKind::CorruptContinuationToken))
            && request.continuation_token.is_some()
        {
            self.record_fault(
                FaultOperation::ListObjects,
                prefix_label,
                FaultKind::CorruptContinuationToken,
                "corrupt_continuation_token",
                self.schedule.framing_bytes_per_op,
            );
            return Err(RemoteObjectError::CorruptContinuationToken {
                detail: "injected expired/corrupt continuation token".to_owned(),
            });
        }
        self.check_pre_effect_fault(FaultOperation::ListObjects, prefix_label, fault)?;

        let cursor_after = match &request.continuation_token {
            Some(token) => {
                let (_tok_epoch, cursor) = listing::decode_continuation_token(token)
                    .map_err(|detail| RemoteObjectError::CorruptContinuationToken { detail })?;
                Some(cursor)
            }
            None => None,
        };

        let mut all_visible: BTreeMap<String, ListedObject> = BTreeMap::new();
        let mut hidden_entries = 0usize;
        let mut ghost_count = 0usize;

        for (key, obj) in &self.keyspace {
            if !prefix_matches(key, request.prefix.as_deref()) {
                continue;
            }
            if let Some(deleted_at) = obj.deleted_at_epoch {
                if self.epoch < deleted_at.saturating_add(self.schedule.ghost_retention_steps) {
                    ghost_count += 1;
                    all_visible.insert(
                        key.clone(),
                        ListedObject {
                            key: key.clone(),
                            digest: obj.digest,
                            etag: obj.etag.clone(),
                            size_bytes: obj.size_bytes,
                            state: PublicationState::Retired,
                            commit_epoch: obj.commit_epoch,
                            is_ghost: true,
                        },
                    );
                }
                continue;
            }
            if obj.visible_at_epoch > self.epoch {
                hidden_entries += 1;
                continue;
            }
            all_visible.insert(
                key.clone(),
                ListedObject {
                    key: key.clone(),
                    digest: obj.digest,
                    etag: obj.etag.clone(),
                    size_bytes: obj.size_bytes,
                    state: PublicationState::Durable,
                    commit_epoch: obj.commit_epoch,
                    is_ghost: false,
                },
            );
        }

        for (digest, meta) in &self.provider_meta {
            if !prefix_matches(&meta.key, request.prefix.as_deref()) {
                continue;
            }
            if let Some(retired_at) = meta.retired_at_epoch {
                if self.epoch < retired_at.saturating_add(self.schedule.ghost_retention_steps) {
                    ghost_count += 1;
                    all_visible.insert(
                        meta.key.clone(),
                        ListedObject {
                            key: meta.key.clone(),
                            digest: *digest,
                            etag: meta.etag.clone(),
                            size_bytes: meta.size_bytes,
                            state: PublicationState::Retired,
                            commit_epoch: meta.commit_epoch,
                            is_ghost: true,
                        },
                    );
                }
                continue;
            }
            if meta.visible_at_epoch > self.epoch {
                hidden_entries += 1;
                continue;
            }
            all_visible.insert(
                meta.key.clone(),
                ListedObject {
                    key: meta.key.clone(),
                    digest: *digest,
                    etag: meta.etag.clone(),
                    size_bytes: meta.size_bytes,
                    state: meta.state,
                    commit_epoch: meta.commit_epoch,
                    is_ghost: false,
                },
            );
        }

        let mut remaining: Vec<ListedObject> = all_visible
            .into_values()
            .filter(|entry| {
                cursor_after
                    .as_deref()
                    .is_none_or(|cursor| entry.key.as_str() > cursor)
            })
            .collect();

        let mut anomalies = Vec::new();
        if hidden_entries > 0 {
            anomalies.push(ListingConsistency::EventualLag { hidden_entries });
        }
        if ghost_count > 0 {
            anomalies.push(ListingConsistency::StaleGhostIncluded { ghost_count });
        }

        let mut page_limit = request.max_keys;
        let mut injected_fault: Option<&'static str> = None;
        if let Some(FaultKind::TruncateListPage { forced_max_keys }) = fault {
            if forced_max_keys < page_limit {
                page_limit = forced_max_keys;
                anomalies.push(ListingConsistency::TruncatedEarly);
                injected_fault = Some(FaultKind::TruncateListPage { forced_max_keys }.as_str());
                self.cost.faults_injected = self.cost.faults_injected.saturating_add(1);
            }
        } else if let Some(FaultKind::PartialListOmission { omit_count }) = fault {
            let omitted = omit_deterministic(&mut remaining, omit_count, &mut self.prng);
            if omitted > 0 {
                anomalies.push(ListingConsistency::PartialOmission {
                    omitted_count: omitted,
                });
                injected_fault = Some(FaultKind::PartialListOmission { omit_count }.as_str());
                self.cost.faults_injected = self.cost.faults_injected.saturating_add(1);
            }
        }

        let is_truncated = remaining.len() > page_limit;
        if is_truncated {
            remaining.truncate(page_limit);
        }
        let next_continuation_token = if is_truncated {
            remaining
                .last()
                .map(|last| listing::encode_continuation_token(self.epoch, &last.key))
        } else {
            None
        };

        let consistency = anomalies
            .first()
            .copied()
            .unwrap_or(ListingConsistency::Consistent);
        let wire_out = self
            .schedule
            .framing_bytes_per_op
            .saturating_add((remaining.len() as u64).saturating_mul(64));
        self.cost.wire_bytes_out = self.cost.wire_bytes_out.saturating_add(wire_out);
        self.record_trace(
            FaultOperation::ListObjects,
            prefix_label,
            injected_fault,
            consistency.as_str(),
            wire_out,
        );

        Ok(ListPage {
            entries: remaining,
            is_truncated,
            next_continuation_token,
            consistency,
            anomalies,
            observed_epoch: self.epoch,
            authoritative_epoch: self.epoch,
        })
    }

    /// Scans all pages of `list_objects` up to `max_pages` (`<= MAX_LIST_PAGES_PER_COLLECT`).
    /// Sets `complete = true` ONLY when pagination terminates cleanly with zero lag, omission,
    /// or stale-ghost anomalies.
    pub fn collect_complete_listing(
        &mut self,
        prefix: Option<String>,
        max_keys_per_page: usize,
        max_pages: usize,
    ) -> Result<ListingCollection<ListedObject>, RemoteObjectError> {
        let cap = max_pages.min(MAX_LIST_PAGES_PER_COLLECT);
        if cap == 0 {
            return Err(RemoteObjectError::InvalidRequest(
                "max_pages must be >= 1".to_owned(),
            ));
        }
        let mut entries = Vec::new();
        let mut warnings = Vec::new();
        let mut token: Option<String> = None;
        let mut pages_fetched = 0usize;
        let mut finished = false;
        let mut last_key: Option<String> = None;

        while pages_fetched < cap {
            let page = self.list_objects(&ListRequest {
                prefix: prefix.clone(),
                continuation_token: token.clone(),
                max_keys: max_keys_per_page,
            })?;
            pages_fetched += 1;
            for anomaly in &page.anomalies {
                if !matches!(anomaly, ListingConsistency::TruncatedEarly) {
                    warnings.push(*anomaly);
                }
            }
            for item in page.entries {
                if let Some(prev) = &last_key
                    && item.key <= *prev
                {
                    return Err(RemoteObjectError::CorruptContinuationToken {
                        detail: "non-monotone listing order detected".to_owned(),
                    });
                }
                last_key = Some(item.key.clone());
                entries.push(item);
            }
            if !page.is_truncated {
                finished = true;
                break;
            }
            let Some(next) = page.next_continuation_token else {
                warnings.push(ListingConsistency::TruncatedEarly);
                break;
            };
            token = Some(next);
        }

        let complete = finished && warnings.is_empty();
        Ok(ListingCollection {
            entries,
            pages_fetched,
            complete,
            consistency_warnings: warnings,
        })
    }

    /// Paginated listing of committed multipart parts for one upload intent.
    pub fn list_multipart_parts(
        &mut self,
        intent_digest: ContentDigest,
        request: &ListRequest,
    ) -> Result<ListPage<PartReceipt>, RemoteObjectError> {
        self.cost.list_ops = self.cost.list_ops.saturating_add(1);
        request
            .validate(self.limits.max_list_page_keys)
            .map_err(RemoteObjectError::InvalidRequest)?;
        let ordinal = self.bump_op(FaultOperation::ListMultipartParts);
        let fault = self.select_fault(
            FaultOperation::ListMultipartParts,
            ordinal,
            Some(intent_digest),
        );
        let label = intent_digest.to_text();

        if matches!(fault, Some(FaultKind::CorruptContinuationToken))
            && request.continuation_token.is_some()
        {
            self.record_fault(
                FaultOperation::ListMultipartParts,
                &label,
                FaultKind::CorruptContinuationToken,
                "corrupt_continuation_token",
                self.schedule.framing_bytes_per_op,
            );
            return Err(RemoteObjectError::CorruptContinuationToken {
                detail: "injected expired multipart part continuation token".to_owned(),
            });
        }
        self.check_pre_effect_fault(FaultOperation::ListMultipartParts, &label, fault)?;

        let cursor_after: Option<u64> = match &request.continuation_token {
            Some(token) => {
                let (_tok_epoch, cursor) = listing::decode_continuation_token(token)
                    .map_err(|detail| RemoteObjectError::CorruptContinuationToken { detail })?;
                let idx = cursor.parse::<u64>().map_err(|_| {
                    RemoteObjectError::CorruptContinuationToken {
                        detail: "invalid numeric part cursor".to_owned(),
                    }
                })?;
                Some(idx)
            }
            None => None,
        };

        let Some(upload) = self.uploads.get(&intent_digest) else {
            self.record_trace(
                FaultOperation::ListMultipartParts,
                &label,
                None,
                "not_found",
                0,
            );
            return Err(RemoteObjectError::NotFound { target: label });
        };

        let mut hidden_entries = 0usize;
        let mut visible_parts = Vec::new();
        for (&idx, part) in &upload.parts {
            if part.visible_at_epoch > self.epoch {
                hidden_entries += 1;
                continue;
            }
            if cursor_after.is_none_or(|c| idx > c) {
                visible_parts.push(part.receipt.clone());
            }
        }

        let mut anomalies = Vec::new();
        if hidden_entries > 0 || upload.visible_at_epoch > self.epoch {
            anomalies.push(ListingConsistency::EventualLag {
                hidden_entries: hidden_entries
                    .max(usize::from(upload.visible_at_epoch > self.epoch)),
            });
        }

        let mut page_limit = request.max_keys;
        let mut injected_fault: Option<&'static str> = None;
        if let Some(FaultKind::TruncateListPage { forced_max_keys }) = fault {
            if forced_max_keys < page_limit {
                page_limit = forced_max_keys;
                anomalies.push(ListingConsistency::TruncatedEarly);
                injected_fault = Some(FaultKind::TruncateListPage { forced_max_keys }.as_str());
                self.cost.faults_injected = self.cost.faults_injected.saturating_add(1);
            }
        } else if let Some(FaultKind::PartialListOmission { omit_count }) = fault {
            let omitted = omit_deterministic(&mut visible_parts, omit_count, &mut self.prng);
            if omitted > 0 {
                anomalies.push(ListingConsistency::PartialOmission {
                    omitted_count: omitted,
                });
                injected_fault = Some(FaultKind::PartialListOmission { omit_count }.as_str());
                self.cost.faults_injected = self.cost.faults_injected.saturating_add(1);
            }
        }

        let is_truncated = visible_parts.len() > page_limit;
        if is_truncated {
            visible_parts.truncate(page_limit);
        }
        let next_continuation_token = if is_truncated {
            visible_parts
                .last()
                .map(|last| listing::encode_continuation_token(self.epoch, &last.index.to_string()))
        } else {
            None
        };

        let consistency = anomalies
            .first()
            .copied()
            .unwrap_or(ListingConsistency::Consistent);
        self.record_trace(
            FaultOperation::ListMultipartParts,
            &label,
            injected_fault,
            consistency.as_str(),
            self.schedule.framing_bytes_per_op,
        );

        Ok(ListPage {
            entries: visible_parts,
            is_truncated,
            next_continuation_token,
            consistency,
            anomalies,
            observed_epoch: self.epoch,
            authoritative_epoch: self.epoch,
        })
    }

    // ---- Internal helpers ------------------------------------------------

    fn bump_op(&mut self, operation: FaultOperation) -> u64 {
        let entry = self.op_counts.entry(operation).or_insert(0);
        *entry = entry.saturating_add(1);
        *entry
    }

    fn mint_etag(&mut self, prefix: &str) -> ETag {
        self.next_etag_seq = self.next_etag_seq.saturating_add(1);
        ETag(format!(
            "\"sim-{prefix}-{:08x}-{:08x}\"",
            self.epoch, self.next_etag_seq
        ))
    }

    fn mint_upload_id(&mut self) -> UploadId {
        self.next_upload_seq = self.next_upload_seq.saturating_add(1);
        UploadId(format!("sim-upload-{:08x}", self.next_upload_seq))
    }

    fn take_adversarial(&mut self, mode: AdversarialMisbehavior) -> bool {
        if let Some(pos) = self.remaining_adversarial.iter().position(|m| *m == mode) {
            self.remaining_adversarial.remove(pos);
            self.cost.faults_injected = self.cost.faults_injected.saturating_add(1);
            true
        } else {
            false
        }
    }

    fn select_fault(
        &mut self,
        operation: FaultOperation,
        ordinal: u64,
        target: Option<ContentDigest>,
    ) -> Option<FaultKind> {
        for rule in &self.schedule.rules {
            if rule.matches(operation, ordinal, target) {
                return Some(rule.kind);
            }
        }
        let rates = self.schedule.rates;
        if rates.throttle_ppm > 0 && self.prng.hit_ppm(rates.throttle_ppm) {
            return Some(FaultKind::ThrottleRateLimit);
        }
        if rates.fail_before_effect_ppm > 0 && self.prng.hit_ppm(rates.fail_before_effect_ppm) {
            return Some(FaultKind::FailBeforeEffect);
        }
        let is_mutating = matches!(
            operation,
            FaultOperation::Stage
                | FaultOperation::Advance
                | FaultOperation::ActivateRoot
                | FaultOperation::DeactivateRoot
                | FaultOperation::Retire
                | FaultOperation::Initiate
                | FaultOperation::UploadPart
                | FaultOperation::Complete
                | FaultOperation::Abort
                | FaultOperation::PutConditional
                | FaultOperation::DeleteObject
        );
        if is_mutating && rates.lost_ack_ppm > 0 && self.prng.hit_ppm(rates.lost_ack_ppm) {
            return Some(FaultKind::LostAckAfterEffect);
        }
        let is_listing = matches!(
            operation,
            FaultOperation::ListObjects | FaultOperation::ListMultipartParts
        );
        if is_listing {
            if rates.partial_list_omission_ppm > 0
                && self.prng.hit_ppm(rates.partial_list_omission_ppm)
            {
                return Some(FaultKind::PartialListOmission { omit_count: 1 });
            }
            if rates.truncate_list_ppm > 0 && self.prng.hit_ppm(rates.truncate_list_ppm) {
                return Some(FaultKind::TruncateListPage { forced_max_keys: 1 });
            }
        }
        None
    }

    fn check_pre_effect_fault(
        &mut self,
        operation: FaultOperation,
        target: &str,
        fault: Option<FaultKind>,
    ) -> Result<(), RemoteObjectError> {
        match fault {
            Some(FaultKind::FailBeforeEffect) => {
                self.record_fault(
                    operation,
                    target,
                    FaultKind::FailBeforeEffect,
                    "transient_unavailable",
                    0,
                );
                Err(RemoteObjectError::TransientUnavailable {
                    operation,
                    detail: "injected pre-effect outage".to_owned(),
                })
            }
            Some(FaultKind::ThrottleRateLimit) => {
                self.record_fault(
                    operation,
                    target,
                    FaultKind::ThrottleRateLimit,
                    "rate_limited",
                    0,
                );
                Err(RemoteObjectError::RateLimited { operation })
            }
            Some(FaultKind::QuotaExceeded) => {
                self.record_fault(
                    operation,
                    target,
                    FaultKind::QuotaExceeded,
                    "quota_exceeded",
                    0,
                );
                Err(RemoteObjectError::QuotaExceeded {
                    detail: "injected quota ceiling".to_owned(),
                })
            }
            _ => Ok(()),
        }
    }

    fn record_fault(
        &mut self,
        operation: FaultOperation,
        target: &str,
        fault: FaultKind,
        outcome: &str,
        wire_bytes: u64,
    ) {
        self.cost.faults_injected = self.cost.faults_injected.saturating_add(1);
        self.record_trace(operation, target, Some(fault.as_str()), outcome, wire_bytes);
    }

    fn record_trace(
        &mut self,
        operation: FaultOperation,
        target: &str,
        fault: Option<&'static str>,
        outcome: &str,
        wire_bytes: u64,
    ) {
        self.trace_seq = self.trace_seq.saturating_add(1);
        if self.trace.len() >= self.limits.max_trace_entries {
            self.trace_truncated = true;
            return;
        }
        let bounded_target = if target.len() > 160 {
            target[..160].to_owned()
        } else {
            target.to_owned()
        };
        self.trace.push(SimulatorTraceEntry {
            seq: self.trace_seq,
            epoch: self.epoch,
            operation,
            target: bounded_target,
            fault,
            outcome: outcome.to_owned(),
            wire_bytes,
        });
    }

    fn count_active_ghosts(&self) -> usize {
        let mut ghosts = 0usize;
        for meta in self.provider_meta.values() {
            if let Some(retired_at) = meta.retired_at_epoch
                && self.epoch < retired_at.saturating_add(self.schedule.ghost_retention_steps)
            {
                ghosts += 1;
            }
        }
        for obj in self.keyspace.values() {
            if let Some(deleted_at) = obj.deleted_at_epoch
                && self.epoch < deleted_at.saturating_add(self.schedule.ghost_retention_steps)
            {
                ghosts += 1;
            }
        }
        ghosts
    }

    fn admit_transport_call(
        &mut self,
        cx: &mut TransportCx<'_>,
        expected_op: TransportOperation,
        fault: Option<FaultKind>,
    ) -> Result<(), String> {
        if cx.operation() != expected_op {
            return Err("transport operation mismatch".to_owned());
        }
        let check_now = match fault {
            Some(FaultKind::ClockStepOnCheckpoint { delta_ns }) => {
                self.cost.faults_injected = self.cost.faults_injected.saturating_add(1);
                TimestampNs(cx.now().0.saturating_add(delta_ns))
            }
            _ => cx.now(),
        };
        cx.checkpoint(check_now).map_err(|e| e.to_string())?;
        let framing = self.schedule.framing_bytes_per_op;
        if framing > 0 {
            cx.charge_io(cx.now(), framing, framing)
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

fn validate_key(key: &str) -> Result<(), RemoteObjectError> {
    if key.trim().is_empty() || key.len() > MAX_KEY_BYTES || key.chars().any(char::is_control) {
        return Err(RemoteObjectError::InvalidRequest(
            "key must be non-empty, <= 1024 bytes, and free of control characters".to_owned(),
        ));
    }
    Ok(())
}

fn prefix_matches(key: &str, prefix: Option<&str>) -> bool {
    prefix.is_none_or(|p| key.starts_with(p))
}

fn omit_deterministic<T>(
    items: &mut Vec<T>,
    omit_count: usize,
    prng: &mut DeterministicPrng,
) -> usize {
    let to_omit = omit_count.min(items.len());
    for _ in 0..to_omit {
        let idx = prng.next_index(items.len());
        items.remove(idx);
    }
    to_omit
}

// =========================================================================
// ObjectStoreProvider (FSS-061 / FSS-062)
// =========================================================================

impl ObjectStoreProvider for RemoteProviderSimulator {
    fn stage(&mut self, bytes: &[u8]) -> Result<ContentDigest, ProviderError> {
        self.cost.provider_ops = self.cost.provider_ops.saturating_add(1);
        let digest = ContentDigest::sha256(bytes);
        let label = digest.to_text();
        let ordinal = self.bump_op(FaultOperation::Stage);
        let fault = self.select_fault(FaultOperation::Stage, ordinal, Some(digest));

        match fault {
            Some(FaultKind::FailBeforeEffect) => {
                self.record_fault(
                    FaultOperation::Stage,
                    &label,
                    FaultKind::FailBeforeEffect,
                    "transient_unavailable",
                    0,
                );
                return Err(ProviderError::Custody(
                    "remote stage failed before effect".to_owned(),
                ));
            }
            Some(FaultKind::ThrottleRateLimit) => {
                self.record_fault(
                    FaultOperation::Stage,
                    &label,
                    FaultKind::ThrottleRateLimit,
                    "rate_limited",
                    0,
                );
                return Err(ProviderError::Custody(
                    "remote stage rate limited".to_owned(),
                ));
            }
            Some(FaultKind::QuotaExceeded) => {
                self.record_fault(
                    FaultOperation::Stage,
                    &label,
                    FaultKind::QuotaExceeded,
                    "quota_exceeded",
                    0,
                );
                return Err(ProviderError::Custody(
                    "remote stage quota exceeded".to_owned(),
                ));
            }
            _ => {}
        }

        let staged = self.inner.stage(bytes)?;
        let lag = match fault {
            Some(FaultKind::EventualVisibilityLag { lag_steps }) => lag_steps,
            _ => self.schedule.default_visibility_lag,
        };
        let commit_epoch = self.epoch;
        let visible_at_epoch = commit_epoch.saturating_add(lag);
        if !self.provider_meta.contains_key(&staged) {
            let etag = self.mint_etag("prov");
            self.provider_meta.insert(
                staged,
                ProviderObjectMeta {
                    key: format!("objects/{}", staged.to_text()),
                    etag,
                    size_bytes: bytes.len() as u64,
                    state: PublicationState::Staged,
                    commit_epoch,
                    visible_at_epoch,
                    retired_at_epoch: None,
                },
            );
        }
        let wire_in = bytes.len() as u64;
        self.cost.wire_bytes_in = self.cost.wire_bytes_in.saturating_add(wire_in);
        if matches!(fault, Some(FaultKind::LostAckAfterEffect)) {
            self.record_fault(
                FaultOperation::Stage,
                &label,
                FaultKind::LostAckAfterEffect,
                "lost_acknowledgement",
                wire_in,
            );
            return Err(ProviderError::Custody(
                "remote stage committed but acknowledgement was lost".to_owned(),
            ));
        }
        self.record_trace(FaultOperation::Stage, &label, None, "ok", wire_in);
        Ok(staged)
    }

    fn advance(
        &mut self,
        digest: ContentDigest,
        to: PublicationState,
    ) -> Result<PublicationState, ProviderError> {
        self.cost.provider_ops = self.cost.provider_ops.saturating_add(1);
        let label = digest.to_text();
        let ordinal = self.bump_op(FaultOperation::Advance);
        let fault = self.select_fault(FaultOperation::Advance, ordinal, Some(digest));

        if matches!(
            fault,
            Some(FaultKind::FailBeforeEffect | FaultKind::ThrottleRateLimit)
        ) {
            let kind = fault.unwrap_or(FaultKind::FailBeforeEffect);
            self.record_fault(FaultOperation::Advance, &label, kind, kind.as_str(), 0);
            return Err(ProviderError::Custody(format!(
                "remote advance refused: {}",
                kind.as_str()
            )));
        }

        let next = self.inner.advance(digest, to)?;
        let lag = match fault {
            Some(FaultKind::EventualVisibilityLag { lag_steps }) => lag_steps,
            _ => self.schedule.default_visibility_lag,
        };
        if let Some(meta) = self.provider_meta.get_mut(&digest) {
            meta.state = next;
            meta.commit_epoch = self.epoch;
            meta.visible_at_epoch = self.epoch.saturating_add(lag);
        }
        if matches!(fault, Some(FaultKind::LostAckAfterEffect)) {
            self.record_fault(
                FaultOperation::Advance,
                &label,
                FaultKind::LostAckAfterEffect,
                "lost_acknowledgement",
                0,
            );
            return Err(ProviderError::Custody(
                "remote advance committed but acknowledgement was lost".to_owned(),
            ));
        }
        self.record_trace(FaultOperation::Advance, &label, None, next.as_str(), 0);
        Ok(next)
    }

    fn activate_root(
        &mut self,
        root: ContentDigest,
        children: &[ContentDigest],
    ) -> Result<(), ProviderError> {
        self.cost.provider_ops = self.cost.provider_ops.saturating_add(1);
        let label = root.to_text();
        let ordinal = self.bump_op(FaultOperation::ActivateRoot);
        let fault = self.select_fault(FaultOperation::ActivateRoot, ordinal, Some(root));

        if matches!(
            fault,
            Some(FaultKind::FailBeforeEffect | FaultKind::ThrottleRateLimit)
        ) {
            let kind = fault.unwrap_or(FaultKind::FailBeforeEffect);
            self.record_fault(FaultOperation::ActivateRoot, &label, kind, kind.as_str(), 0);
            return Err(ProviderError::Custody(format!(
                "remote activate_root refused: {}",
                kind.as_str()
            )));
        }

        self.inner.activate_root(root, children)?;
        if matches!(fault, Some(FaultKind::LostAckAfterEffect)) {
            self.record_fault(
                FaultOperation::ActivateRoot,
                &label,
                FaultKind::LostAckAfterEffect,
                "lost_acknowledgement",
                0,
            );
            return Err(ProviderError::Custody(
                "remote activate_root committed but acknowledgement was lost".to_owned(),
            ));
        }
        self.record_trace(FaultOperation::ActivateRoot, &label, None, "ok", 0);
        Ok(())
    }

    fn deactivate_root(&mut self, root: ContentDigest) -> Result<(), ProviderError> {
        self.cost.provider_ops = self.cost.provider_ops.saturating_add(1);
        let label = root.to_text();
        let ordinal = self.bump_op(FaultOperation::DeactivateRoot);
        let fault = self.select_fault(FaultOperation::DeactivateRoot, ordinal, Some(root));
        if matches!(
            fault,
            Some(FaultKind::FailBeforeEffect | FaultKind::ThrottleRateLimit)
        ) {
            let kind = fault.unwrap_or(FaultKind::FailBeforeEffect);
            self.record_fault(
                FaultOperation::DeactivateRoot,
                &label,
                kind,
                kind.as_str(),
                0,
            );
            return Err(ProviderError::Custody(format!(
                "remote deactivate_root refused: {}",
                kind.as_str()
            )));
        }
        self.inner.deactivate_root(root)?;
        self.record_trace(FaultOperation::DeactivateRoot, &label, None, "ok", 0);
        Ok(())
    }

    fn retire(
        &mut self,
        digest: ContentDigest,
        deletion_authority_witness: ContentDigest,
    ) -> Result<(), ProviderError> {
        self.cost.provider_ops = self.cost.provider_ops.saturating_add(1);
        let label = digest.to_text();
        let ordinal = self.bump_op(FaultOperation::Retire);
        let fault = self.select_fault(FaultOperation::Retire, ordinal, Some(digest));
        if matches!(
            fault,
            Some(FaultKind::FailBeforeEffect | FaultKind::ThrottleRateLimit)
        ) {
            let kind = fault.unwrap_or(FaultKind::FailBeforeEffect);
            self.record_fault(FaultOperation::Retire, &label, kind, kind.as_str(), 0);
            return Err(ProviderError::Custody(format!(
                "remote retire refused: {}",
                kind.as_str()
            )));
        }

        self.inner.retire(digest, deletion_authority_witness)?;
        if let Some(meta) = self.provider_meta.get_mut(&digest) {
            meta.state = PublicationState::Retired;
            meta.retired_at_epoch = Some(self.epoch);
        }
        if matches!(fault, Some(FaultKind::LostAckAfterEffect)) {
            self.record_fault(
                FaultOperation::Retire,
                &label,
                FaultKind::LostAckAfterEffect,
                "lost_acknowledgement",
                0,
            );
            return Err(ProviderError::Custody(
                "remote retire committed but acknowledgement was lost".to_owned(),
            ));
        }
        self.record_trace(FaultOperation::Retire, &label, None, "retired", 0);
        Ok(())
    }

    fn verify_retrievable(
        &mut self,
        digest: ContentDigest,
        now: TimestampNs,
    ) -> Result<RetrievabilityWitness, ProviderError> {
        self.cost.provider_ops = self.cost.provider_ops.saturating_add(1);
        let label = digest.to_text();
        let ordinal = self.bump_op(FaultOperation::VerifyRetrievable);
        let fault = self.select_fault(FaultOperation::VerifyRetrievable, ordinal, Some(digest));

        if matches!(
            fault,
            Some(FaultKind::FailBeforeEffect | FaultKind::ThrottleRateLimit)
        ) {
            let kind = fault.unwrap_or(FaultKind::FailBeforeEffect);
            self.record_fault(
                FaultOperation::VerifyRetrievable,
                &label,
                kind,
                kind.as_str(),
                0,
            );
            return Err(ProviderError::NotRetrievable {
                digest,
                reason: format!("remote probe unavailable: {}", kind.as_str()),
            });
        }

        if let Some(visible_at) = self
            .provider_meta
            .get(&digest)
            .map(|meta| meta.visible_at_epoch)
            .filter(|&vis| vis > self.epoch)
        {
            self.record_trace(
                FaultOperation::VerifyRetrievable,
                &label,
                Some("eventual_visibility_lag"),
                "not_retrievable",
                0,
            );
            return Err(ProviderError::NotRetrievable {
                digest,
                reason: format!(
                    "eventual_visibility_lag: current epoch {} < visible_at {}",
                    self.epoch, visible_at
                ),
            });
        }

        if matches!(fault, Some(FaultKind::CorruptReadback)) {
            self.cost.corruptions_caught = self.cost.corruptions_caught.saturating_add(1);
            self.record_fault(
                FaultOperation::VerifyRetrievable,
                &label,
                FaultKind::CorruptReadback,
                "not_retrievable",
                0,
            );
            return Err(ProviderError::NotRetrievable {
                digest,
                reason: "readback_digest_mismatch".to_owned(),
            });
        }

        let witness = self.inner.verify_retrievable(digest, now)?;
        let size = self
            .provider_meta
            .get(&digest)
            .map_or(0, |meta| meta.size_bytes);
        self.cost.wire_bytes_out = self.cost.wire_bytes_out.saturating_add(size);
        self.record_trace(FaultOperation::VerifyRetrievable, &label, None, "ok", size);
        Ok(witness)
    }

    fn state(&self, digest: ContentDigest) -> Result<PublicationState, ProviderError> {
        self.inner.state(digest)
    }
}

// =========================================================================
// MultipartTransport (FSS-130 / FSS-063)
// =========================================================================

impl MultipartTransport for RemoteProviderSimulator {
    fn initiate(
        &mut self,
        cx: &mut TransportCx<'_>,
        intent: &UploadIntent,
    ) -> Result<UploadId, String> {
        self.cost.initiate_ops = self.cost.initiate_ops.saturating_add(1);
        let ordinal = self.bump_op(FaultOperation::Initiate);
        let fault = self.select_fault(FaultOperation::Initiate, ordinal, Some(intent.digest()));
        self.admit_transport_call(cx, TransportOperation::Initiate, fault)?;
        let label = intent.digest().to_text();

        match fault {
            Some(FaultKind::FailBeforeEffect) => {
                self.record_fault(
                    FaultOperation::Initiate,
                    &label,
                    FaultKind::FailBeforeEffect,
                    "transient_unavailable",
                    self.schedule.framing_bytes_per_op,
                );
                return Err("remote initiate failed before effect".to_owned());
            }
            Some(FaultKind::ThrottleRateLimit) => {
                self.record_fault(
                    FaultOperation::Initiate,
                    &label,
                    FaultKind::ThrottleRateLimit,
                    "rate_limited",
                    self.schedule.framing_bytes_per_op,
                );
                return Err("remote initiate throttled (429/503)".to_owned());
            }
            Some(FaultKind::QuotaExceeded) => {
                self.record_fault(
                    FaultOperation::Initiate,
                    &label,
                    FaultKind::QuotaExceeded,
                    "quota_exceeded",
                    self.schedule.framing_bytes_per_op,
                );
                return Err("remote upload quota exceeded".to_owned());
            }
            _ => {}
        }

        let upload_id = if let Some(existing) = self.uploads.get(&intent.digest()) {
            if &existing.intent != intent {
                return Err("intent collision under existing digest".to_owned());
            }
            existing.upload_id.clone()
        } else {
            if self.uploads.len() >= self.limits.max_uploads {
                self.record_trace(
                    FaultOperation::Initiate,
                    &label,
                    None,
                    "quota_exceeded",
                    self.schedule.framing_bytes_per_op,
                );
                return Err(format!(
                    "simulator max_uploads ({}) reached",
                    self.limits.max_uploads
                ));
            }
            let lag = match fault {
                Some(FaultKind::EventualVisibilityLag { lag_steps }) => lag_steps,
                _ => self.schedule.default_visibility_lag,
            };
            let upload_id = self.mint_upload_id();
            let visible_at_epoch = self.epoch.saturating_add(lag);
            self.uploads.insert(
                intent.digest(),
                SimulatedUpload {
                    upload_id: upload_id.clone(),
                    intent: intent.clone(),
                    phase: RemoteUploadPhase::Active,
                    commit_epoch: self.epoch,
                    visible_at_epoch,
                    parts: BTreeMap::new(),
                    complete_dispatched: false,
                },
            );
            self.upload_id_to_intent
                .insert(upload_id.clone(), intent.digest());
            upload_id
        };

        self.cost.wire_bytes_in = self
            .cost
            .wire_bytes_in
            .saturating_add(self.schedule.framing_bytes_per_op);

        if matches!(fault, Some(FaultKind::LostAckAfterEffect)) {
            self.record_fault(
                FaultOperation::Initiate,
                &label,
                FaultKind::LostAckAfterEffect,
                "lost_acknowledgement",
                self.schedule.framing_bytes_per_op,
            );
            return Err("initiation committed remotely but ACK lost".to_owned());
        }

        self.record_trace(
            FaultOperation::Initiate,
            &label,
            None,
            "ok",
            self.schedule.framing_bytes_per_op,
        );
        Ok(upload_id)
    }

    fn upload_part(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        chunk: &PlannedChunk,
        bytes: &[u8],
        content_digest: ContentDigest,
    ) -> Result<PartReceipt, String> {
        self.cost.upload_part_ops = self.cost.upload_part_ops.saturating_add(1);
        let ordinal = self.bump_op(FaultOperation::UploadPart);
        let fault = self.select_fault(FaultOperation::UploadPart, ordinal, Some(content_digest));
        self.admit_transport_call(cx, TransportOperation::UploadPart, fault)?;
        let label = format!("{}:part:{}", upload.0, chunk.index);

        match fault {
            Some(FaultKind::FailBeforeEffect) => {
                self.record_fault(
                    FaultOperation::UploadPart,
                    &label,
                    FaultKind::FailBeforeEffect,
                    "transient_unavailable",
                    self.schedule.framing_bytes_per_op,
                );
                return Err("remote upload_part failed before effect".to_owned());
            }
            Some(FaultKind::ThrottleRateLimit) => {
                self.record_fault(
                    FaultOperation::UploadPart,
                    &label,
                    FaultKind::ThrottleRateLimit,
                    "rate_limited",
                    self.schedule.framing_bytes_per_op,
                );
                return Err("remote upload_part throttled (429/503)".to_owned());
            }
            Some(FaultKind::QuotaExceeded) => {
                self.record_fault(
                    FaultOperation::UploadPart,
                    &label,
                    FaultKind::QuotaExceeded,
                    "quota_exceeded",
                    self.schedule.framing_bytes_per_op,
                );
                return Err("remote upload_part quota exceeded".to_owned());
            }
            _ => {}
        }

        if u64::try_from(bytes.len()).ok() != Some(chunk.len)
            || ContentDigest::sha256(bytes) != content_digest
        {
            return Err("part checksum or byte length precondition failed".to_owned());
        }

        let intent_digest = *self
            .upload_id_to_intent
            .get(upload)
            .ok_or_else(|| "unknown upload id".to_owned())?;
        let lag = match fault {
            Some(FaultKind::EventualVisibilityLag { lag_steps }) => lag_steps,
            _ => self.schedule.default_visibility_lag,
        };
        let etag = self.mint_etag(&format!("part-{}", chunk.index));
        let commit_epoch = self.epoch;
        let visible_at_epoch = commit_epoch.saturating_add(lag);

        let stored_receipt = {
            let entry = self
                .uploads
                .get_mut(&intent_digest)
                .ok_or_else(|| "upload record missing".to_owned())?;
            if entry.phase != RemoteUploadPhase::Active {
                return Err("upload is not active".to_owned());
            }
            if let Some(existing) = entry.parts.get(&chunk.index) {
                if existing.receipt.content_digest != content_digest {
                    return Err("conflicting part bytes for already-committed index".to_owned());
                }
                existing.receipt.clone()
            } else {
                let receipt = PartReceipt {
                    index: chunk.index,
                    content_digest,
                    etag,
                };
                entry.parts.insert(
                    chunk.index,
                    SimulatedPart {
                        receipt: receipt.clone(),
                        commit_epoch,
                        visible_at_epoch,
                        len: chunk.len,
                    },
                );
                receipt
            }
        };

        let wire_in = chunk.len.saturating_add(self.schedule.framing_bytes_per_op);
        self.cost.wire_bytes_in = self.cost.wire_bytes_in.saturating_add(wire_in);

        if matches!(fault, Some(FaultKind::LostAckAfterEffect)) {
            self.record_fault(
                FaultOperation::UploadPart,
                &label,
                FaultKind::LostAckAfterEffect,
                "lost_acknowledgement",
                wire_in,
            );
            return Err("part uploaded remotely but ACK lost".to_owned());
        }

        let mut returned = stored_receipt;
        if self.take_adversarial(AdversarialMisbehavior::WrongPartChecksumOnce) {
            returned.content_digest = ContentDigest::sha256(b"adversarial-wrong-part-digest");
            self.record_trace(
                FaultOperation::UploadPart,
                &label,
                Some(AdversarialMisbehavior::WrongPartChecksumOnce.as_str()),
                "adversarial_wrong_checksum",
                wire_in,
            );
            return Ok(returned);
        }

        self.record_trace(FaultOperation::UploadPart, &label, None, "ok", wire_in);
        Ok(returned)
    }

    fn complete(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        intent: &UploadIntent,
        parts: &[PartReceipt],
    ) -> Result<(), String> {
        self.cost.complete_ops = self.cost.complete_ops.saturating_add(1);
        let ordinal = self.bump_op(FaultOperation::Complete);
        let fault = self.select_fault(FaultOperation::Complete, ordinal, Some(intent.digest()));
        self.admit_transport_call(cx, TransportOperation::Complete, fault)?;
        let label = intent.digest().to_text();

        match fault {
            Some(FaultKind::FailBeforeEffect) => {
                self.record_fault(
                    FaultOperation::Complete,
                    &label,
                    FaultKind::FailBeforeEffect,
                    "transient_unavailable",
                    self.schedule.framing_bytes_per_op,
                );
                return Err("remote complete failed before effect".to_owned());
            }
            Some(FaultKind::ThrottleRateLimit) => {
                self.record_fault(
                    FaultOperation::Complete,
                    &label,
                    FaultKind::ThrottleRateLimit,
                    "rate_limited",
                    self.schedule.framing_bytes_per_op,
                );
                return Err("remote complete throttled (429/503)".to_owned());
            }
            _ => {}
        }

        let lag = match fault {
            Some(FaultKind::EventualVisibilityLag { lag_steps }) => lag_steps,
            _ => self.schedule.default_visibility_lag,
        };
        let commit_epoch = self.epoch;
        let visible_at_epoch = commit_epoch.saturating_add(lag);

        let entry = self
            .uploads
            .get_mut(&intent.digest())
            .ok_or_else(|| "unknown upload intent".to_owned())?;
        if entry.upload_id != *upload || &entry.intent != intent {
            return Err("upload identity or intent mismatch on complete".to_owned());
        }
        if entry.phase == RemoteUploadPhase::Aborted {
            return Err("cannot complete an already aborted upload".to_owned());
        }
        let expected_parts: Vec<PartReceipt> =
            entry.parts.values().map(|p| p.receipt.clone()).collect();
        if parts != expected_parts.as_slice() {
            return Err("complete part list differs from committed parts".to_owned());
        }
        entry.phase = RemoteUploadPhase::Completed;
        entry.complete_dispatched = true;
        entry.commit_epoch = commit_epoch;
        entry.visible_at_epoch = visible_at_epoch;

        self.cost.wire_bytes_in = self
            .cost
            .wire_bytes_in
            .saturating_add(self.schedule.framing_bytes_per_op);

        if matches!(fault, Some(FaultKind::LostAckAfterEffect)) {
            self.record_fault(
                FaultOperation::Complete,
                &label,
                FaultKind::LostAckAfterEffect,
                "lost_acknowledgement",
                self.schedule.framing_bytes_per_op,
            );
            return Err("completion committed remotely but ACK lost".to_owned());
        }

        self.record_trace(
            FaultOperation::Complete,
            &label,
            None,
            "completed",
            self.schedule.framing_bytes_per_op,
        );
        Ok(())
    }

    fn abort(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        intent: &UploadIntent,
    ) -> Result<(), String> {
        self.cost.abort_ops = self.cost.abort_ops.saturating_add(1);
        let ordinal = self.bump_op(FaultOperation::Abort);
        let fault = self.select_fault(FaultOperation::Abort, ordinal, Some(intent.digest()));
        self.admit_transport_call(cx, TransportOperation::Abort, fault)?;
        let label = intent.digest().to_text();

        match fault {
            Some(FaultKind::FailBeforeEffect) => {
                self.record_fault(
                    FaultOperation::Abort,
                    &label,
                    FaultKind::FailBeforeEffect,
                    "transient_unavailable",
                    self.schedule.framing_bytes_per_op,
                );
                return Err("remote abort failed before effect".to_owned());
            }
            Some(FaultKind::ThrottleRateLimit) => {
                self.record_fault(
                    FaultOperation::Abort,
                    &label,
                    FaultKind::ThrottleRateLimit,
                    "rate_limited",
                    self.schedule.framing_bytes_per_op,
                );
                return Err("remote abort throttled (429/503)".to_owned());
            }
            _ => {}
        }

        let lag = match fault {
            Some(FaultKind::EventualVisibilityLag { lag_steps }) => lag_steps,
            _ => self.schedule.default_visibility_lag,
        };
        let commit_epoch = self.epoch;
        let visible_at_epoch = commit_epoch.saturating_add(lag);

        let entry = self
            .uploads
            .get_mut(&intent.digest())
            .ok_or_else(|| "unknown upload intent".to_owned())?;
        if entry.upload_id != *upload || &entry.intent != intent {
            return Err("upload identity or intent mismatch on abort".to_owned());
        }
        if entry.phase == RemoteUploadPhase::Completed {
            return Err("cannot abort an already completed upload".to_owned());
        }
        entry.phase = RemoteUploadPhase::Aborted;
        entry.commit_epoch = commit_epoch;
        entry.visible_at_epoch = visible_at_epoch;

        self.cost.wire_bytes_in = self
            .cost
            .wire_bytes_in
            .saturating_add(self.schedule.framing_bytes_per_op);

        if matches!(fault, Some(FaultKind::LostAckAfterEffect)) {
            self.record_fault(
                FaultOperation::Abort,
                &label,
                FaultKind::LostAckAfterEffect,
                "lost_acknowledgement",
                self.schedule.framing_bytes_per_op,
            );
            return Err("abort committed remotely but ACK lost".to_owned());
        }

        self.record_trace(
            FaultOperation::Abort,
            &label,
            None,
            "aborted",
            self.schedule.framing_bytes_per_op,
        );
        Ok(())
    }

    fn reconcile(
        &mut self,
        cx: &mut TransportCx<'_>,
        intent: &UploadIntent,
    ) -> Result<Reconciliation, String> {
        self.cost.reconcile_ops = self.cost.reconcile_ops.saturating_add(1);
        let ordinal = self.bump_op(FaultOperation::Reconcile);
        let fault = self.select_fault(FaultOperation::Reconcile, ordinal, Some(intent.digest()));
        self.admit_transport_call(cx, TransportOperation::Reconcile, fault)?;
        let label = intent.digest().to_text();

        match fault {
            Some(FaultKind::FailBeforeEffect) => {
                self.record_fault(
                    FaultOperation::Reconcile,
                    &label,
                    FaultKind::FailBeforeEffect,
                    "transient_unavailable",
                    self.schedule.framing_bytes_per_op,
                );
                return Err("remote reconcile query failed".to_owned());
            }
            Some(FaultKind::ThrottleRateLimit) => {
                self.record_fault(
                    FaultOperation::Reconcile,
                    &label,
                    FaultKind::ThrottleRateLimit,
                    "rate_limited",
                    self.schedule.framing_bytes_per_op,
                );
                return Err("remote reconcile throttled (429/503)".to_owned());
            }
            Some(
                FaultKind::PartialListOmission { .. } | FaultKind::EventualVisibilityLag { .. },
            ) => {
                let kind = fault.unwrap_or(FaultKind::PartialListOmission { omit_count: 1 });
                self.cost.unknown_reconciliations =
                    self.cost.unknown_reconciliations.saturating_add(1);
                self.record_fault(
                    FaultOperation::Reconcile,
                    &label,
                    kind,
                    "unknown",
                    self.schedule.framing_bytes_per_op,
                );
                return Ok(Reconciliation {
                    intent_digest: intent.digest(),
                    state: ProviderUploadState::Unknown,
                });
            }
            _ => {}
        }

        // Check opt-in adversarial misbehaviors first so negative-control tests can prove
        // `MultipartSession` refuses lying providers.
        if self.take_adversarial(AdversarialMisbehavior::WrongIntentDigestOnReconcileOnce) {
            self.record_trace(
                FaultOperation::Reconcile,
                &label,
                Some(AdversarialMisbehavior::WrongIntentDigestOnReconcileOnce.as_str()),
                "adversarial_wrong_intent",
                self.schedule.framing_bytes_per_op,
            );
            return Ok(Reconciliation {
                intent_digest: ContentDigest::sha256(b"adversarial-wrong-intent"),
                state: ProviderUploadState::Unknown,
            });
        }

        let Some(entry) = self.uploads.get(&intent.digest()).cloned() else {
            self.record_trace(
                FaultOperation::Reconcile,
                &label,
                None,
                "not_started",
                self.schedule.framing_bytes_per_op,
            );
            return Ok(Reconciliation {
                intent_digest: intent.digest(),
                state: ProviderUploadState::NotStarted,
            });
        };

        if self.take_adversarial(AdversarialMisbehavior::ForgedCompletedWithoutCompleteOnce) {
            let parts: Vec<PartReceipt> = entry.parts.values().map(|p| p.receipt.clone()).collect();
            self.record_trace(
                FaultOperation::Reconcile,
                &label,
                Some(AdversarialMisbehavior::ForgedCompletedWithoutCompleteOnce.as_str()),
                "adversarial_forged_completed",
                self.schedule.framing_bytes_per_op,
            );
            return Ok(Reconciliation {
                intent_digest: intent.digest(),
                state: ProviderUploadState::Completed {
                    upload: entry.upload_id,
                    manifest_root: intent.manifest_root(),
                    parts,
                },
            });
        }

        if self.take_adversarial(AdversarialMisbehavior::UnexpectedUploadIdOnReconcileOnce) {
            let parts: Vec<PartReceipt> = entry.parts.values().map(|p| p.receipt.clone()).collect();
            self.record_trace(
                FaultOperation::Reconcile,
                &label,
                Some(AdversarialMisbehavior::UnexpectedUploadIdOnReconcileOnce.as_str()),
                "adversarial_wrong_upload_id",
                self.schedule.framing_bytes_per_op,
            );
            return Ok(Reconciliation {
                intent_digest: intent.digest(),
                state: ProviderUploadState::Active {
                    upload: UploadId("adversarial-forged-upload-id".to_owned()),
                    parts,
                },
            });
        }

        if self.take_adversarial(AdversarialMisbehavior::OmitAcknowledgedPartInActiveReconcileOnce)
        {
            let mut parts: Vec<PartReceipt> =
                entry.parts.values().map(|p| p.receipt.clone()).collect();
            if !parts.is_empty() {
                parts.pop();
            }
            self.record_trace(
                FaultOperation::Reconcile,
                &label,
                Some(AdversarialMisbehavior::OmitAcknowledgedPartInActiveReconcileOnce.as_str()),
                "adversarial_omitted_part",
                self.schedule.framing_bytes_per_op,
            );
            return Ok(Reconciliation {
                intent_digest: intent.digest(),
                state: ProviderUploadState::Active {
                    upload: entry.upload_id,
                    parts,
                },
            });
        }

        // Honest eventual-consistency rule: if the upload's latest state transition OR any
        // committed part is still lagging behind `self.epoch`, OR a paginated part scan sees
        // any omission/lag anomaly, we MUST report `ProviderUploadState::Unknown` — never a
        // partial `Active` inventory or premature terminal state.
        let any_part_lagging = entry
            .parts
            .values()
            .any(|part| part.visible_at_epoch > self.epoch);
        if entry.visible_at_epoch > self.epoch || any_part_lagging {
            self.cost.unknown_reconciliations = self.cost.unknown_reconciliations.saturating_add(1);
            self.record_trace(
                FaultOperation::Reconcile,
                &label,
                Some("eventual_visibility_lag"),
                "unknown",
                self.schedule.framing_bytes_per_op,
            );
            return Ok(Reconciliation {
                intent_digest: intent.digest(),
                state: ProviderUploadState::Unknown,
            });
        }

        // Scan part inventory through the real paginated `list_multipart_parts` path so
        // partial-list faults on part enumeration also preserve honesty (`Unknown`).
        let mut collected_parts = Vec::new();
        let mut token: Option<String> = None;
        let mut pages = 0usize;
        loop {
            if pages >= MAX_LIST_PAGES_PER_COLLECT {
                self.cost.unknown_reconciliations =
                    self.cost.unknown_reconciliations.saturating_add(1);
                self.record_trace(
                    FaultOperation::Reconcile,
                    &label,
                    Some("list_page_ceiling"),
                    "unknown",
                    self.schedule.framing_bytes_per_op,
                );
                return Ok(Reconciliation {
                    intent_digest: intent.digest(),
                    state: ProviderUploadState::Unknown,
                });
            }
            let page = match self.list_multipart_parts(
                intent.digest(),
                &ListRequest {
                    prefix: None,
                    continuation_token: token.clone(),
                    max_keys: self.limits.max_list_page_keys,
                },
            ) {
                Ok(p) => p,
                Err(_) => {
                    self.cost.unknown_reconciliations =
                        self.cost.unknown_reconciliations.saturating_add(1);
                    self.record_trace(
                        FaultOperation::Reconcile,
                        &label,
                        Some("part_list_error"),
                        "unknown",
                        self.schedule.framing_bytes_per_op,
                    );
                    return Ok(Reconciliation {
                        intent_digest: intent.digest(),
                        state: ProviderUploadState::Unknown,
                    });
                }
            };
            pages += 1;
            let incomplete_view = page.anomalies.iter().any(|a| {
                matches!(
                    a,
                    ListingConsistency::EventualLag { .. }
                        | ListingConsistency::PartialOmission { .. }
                        | ListingConsistency::StaleGhostIncluded { .. }
                )
            });
            if incomplete_view {
                self.cost.unknown_reconciliations =
                    self.cost.unknown_reconciliations.saturating_add(1);
                self.record_trace(
                    FaultOperation::Reconcile,
                    &label,
                    Some(page.consistency.as_str()),
                    "unknown",
                    self.schedule.framing_bytes_per_op,
                );
                return Ok(Reconciliation {
                    intent_digest: intent.digest(),
                    state: ProviderUploadState::Unknown,
                });
            }
            collected_parts.extend(page.entries);
            if !page.is_truncated {
                break;
            }
            let Some(next) = page.next_continuation_token else {
                self.cost.unknown_reconciliations =
                    self.cost.unknown_reconciliations.saturating_add(1);
                return Ok(Reconciliation {
                    intent_digest: intent.digest(),
                    state: ProviderUploadState::Unknown,
                });
            };
            token = Some(next);
        }

        let state = match entry.phase {
            RemoteUploadPhase::Active => ProviderUploadState::Active {
                upload: entry.upload_id,
                parts: collected_parts,
            },
            RemoteUploadPhase::Completed => ProviderUploadState::Completed {
                upload: entry.upload_id,
                manifest_root: entry.intent.manifest_root(),
                parts: collected_parts,
            },
            RemoteUploadPhase::Aborted => ProviderUploadState::Aborted {
                upload: entry.upload_id,
            },
        };
        let state_label = match &state {
            ProviderUploadState::Active { .. } => "active",
            ProviderUploadState::Completed { .. } => "completed",
            ProviderUploadState::Aborted { .. } => "aborted",
            ProviderUploadState::NotStarted => "not_started",
            ProviderUploadState::Unknown => "unknown",
        };
        self.record_trace(
            FaultOperation::Reconcile,
            &label,
            None,
            state_label,
            self.schedule.framing_bytes_per_op,
        );
        Ok(Reconciliation {
            intent_digest: intent.digest(),
            state,
        })
    }
}
