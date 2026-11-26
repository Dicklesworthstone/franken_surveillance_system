#![forbid(unsafe_code)]
//! Deterministic safe-Rust reducers for ATP semantic transfer, archive publication, and paths.
//!
//! Enforces every invariant from `architecture/atp_lifecycles.json` and `XFER-INV-001..010`:
//! - Layer separation (semantic transfer vs. archive publication vs. archive object vs. path);
//! - Strict monotone transitions with zero skipped steps;
//! - Root-last commit/publication requiring complete verified child closure and live fence;
//! - Separate offered/received/verified/committed/reused counters;
//! - Repair post-digest verification (`XFER-INV-006`);
//! - Path draining with zero live work prior to `Closed` (`XFER-INV-008`);
//! - Archive `Complete` strictly gated on witnessed `RetrievabilityVerified`;
//! - Explicit `IndeterminateTransferObligation` for unresolved remote commits;
//! - Bit-identical journal replay and crash-cut resume equivalence.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalEncoder, ContentDigest, TimestampNs};

use super::crosswalk::{
    ArchiveObjectState, ArchivePublicationState, LifecycleLayer, PathState, SemanticTransferState,
};
use super::journal::{
    JournalRecord, LifecycleEvent, TransferJournal, archive_state_allows_committed_receipt,
};
use super::{
    ATP_LIFECYCLE_FORMAT_VERSION, ATP_LIFECYCLE_RECEIPT_DOMAIN, AtpLifecycleError,
    AuthoritySnapshot, ChildTransferRecord, IndeterminateTransferObligation, LifecycleReceipt,
    MAX_CRITICAL_EXTENSIONS, MAX_FAILURE_DOMAINS, MAX_ID_LABEL_BYTES, MAX_LABEL_BYTES,
    MAX_TRANSFER_CHILDREN, MAX_TRANSFER_PATHS, PathRecord, ProofOfRetrievability,
    StagedChildDisposition, TransferCounters, TransferId, TransferSpec,
};

/// Deterministic reducer coordinating semantic transfer, optional archive publication, multipath
/// transport paths, budgets, fences, and an append-only resumable journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtpLifecycleCoordinator {
    spec: TransferSpec,
    transfer_id: TransferId,
    semantic_state: SemanticTransferState,
    archive_state: Option<ArchivePublicationState>,
    active_fence: u64,
    authority: AuthoritySnapshot,
    counters: TransferCounters,
    children: BTreeMap<ContentDigest, ChildTransferRecord>,
    paths: BTreeMap<String, PathRecord>,
    semantic_history: Vec<SemanticTransferState>,
    archive_history: Vec<ArchivePublicationState>,
    verified_failure_domains: BTreeSet<String>,
    provider_tuple: Option<String>,
    commit_anchor: Option<ContentDigest>,
    proof_of_retrievability: Option<ProofOfRetrievability>,
    reconciliation_obligation: Option<IndeterminateTransferObligation>,
    cancel_requested: bool,
    cancel_reason: Option<String>,
    terminal_reason: Option<String>,
    bytes_spent: u64,
    ops_spent: u64,
    last_timestamp_ns: Option<TimestampNs>,
    journal: TransferJournal,
}

impl AtpLifecycleCoordinator {
    /// Creates a fresh coordinator starting at `Proposed` (and `Planned` when archive mode is on).
    ///
    /// Validates format version, critical extensions, non-empty children, bounds, and initial
    /// authority snapshot before admitting the transfer.
    pub fn new(
        spec: TransferSpec,
        authority: AuthoritySnapshot,
    ) -> Result<Self, AtpLifecycleError> {
        spec.validate()?;
        authority.validate_active(&spec)?;

        let transfer_id = spec.transfer_id();
        let journal = TransferJournal::new(transfer_id, spec.max_journal_records)?;

        let mut children = BTreeMap::new();
        for &(digest, expected_bytes) in &spec.expected_children {
            children.insert(
                digest,
                ChildTransferRecord {
                    digest,
                    expected_bytes,
                    offered: false,
                    received_bytes: 0,
                    repaired: false,
                    post_repair_digest: None,
                    verified: false,
                    archive_object_state: None,
                    disposition: StagedChildDisposition::Pending,
                },
            );
        }

        let archive_state = if spec.archive_enabled {
            Some(ArchivePublicationState::Planned)
        } else {
            None
        };
        let archive_history = archive_state.into_iter().collect();

        Ok(Self {
            active_fence: spec.initial_fence,
            spec,
            transfer_id,
            semantic_state: SemanticTransferState::Proposed,
            archive_state,
            authority,
            counters: TransferCounters::default(),
            children,
            paths: BTreeMap::new(),
            semantic_history: vec![SemanticTransferState::Proposed],
            archive_history,
            verified_failure_domains: BTreeSet::new(),
            provider_tuple: None,
            commit_anchor: None,
            proof_of_retrievability: None,
            reconciliation_obligation: None,
            cancel_requested: false,
            cancel_reason: None,
            terminal_reason: None,
            bytes_spent: 0,
            ops_spent: 0,
            last_timestamp_ns: None,
            journal,
        })
    }

    /// Replays a sequence of decoded, verified journal records from cold state.
    ///
    /// Refuses any invalid transition, stale fence, corrupted digest, or mismatched transfer ID.
    pub fn replay(
        spec: TransferSpec,
        authority: AuthoritySnapshot,
        records: &[JournalRecord],
    ) -> Result<Self, AtpLifecycleError> {
        let mut coordinator = Self::new(spec, authority)?;
        for (idx, record) in records.iter().enumerate() {
            if record.format_version != ATP_LIFECYCLE_FORMAT_VERSION {
                return Err(AtpLifecycleError::IncompatibleVersion {
                    reason: format!("unsupported record version {}", record.format_version),
                });
            }
            if record.seq != idx as u64 {
                return Err(AtpLifecycleError::JournalCorrupt {
                    seq: idx as u64,
                    reason: format!("expected seq {idx}, found {}", record.seq),
                });
            }
            if record.transfer_id != coordinator.transfer_id {
                return Err(AtpLifecycleError::JournalCorrupt {
                    seq: record.seq,
                    reason: "transfer_id mismatch during replay".to_owned(),
                });
            }
            if record.compute_digest() != record.record_digest {
                return Err(AtpLifecycleError::JournalCorrupt {
                    seq: record.seq,
                    reason: "checksum mismatch during replay".to_owned(),
                });
            }
            let expected_prev = coordinator.journal.head_digest();
            if record.prev_digest != expected_prev {
                return Err(AtpLifecycleError::JournalCorrupt {
                    seq: record.seq,
                    reason: "prev_digest chain break during replay".to_owned(),
                });
            }
            let applied = coordinator.apply_event(
                record.fence,
                record.timestamp_ns,
                record.event.clone(),
                record.work_bytes,
                record.work_ops,
            )?;
            if applied.record_digest != record.record_digest {
                return Err(AtpLifecycleError::JournalCorrupt {
                    seq: record.seq,
                    reason: "replayed record digest diverged from journal".to_owned(),
                });
            }
        }
        Ok(coordinator)
    }

    /// Cold-decodes raw framed journal bytes and replays into a live coordinator.
    pub fn resume_from_framed_bytes(
        spec: TransferSpec,
        authority: AuthoritySnapshot,
        framed: &[u8],
    ) -> Result<Self, AtpLifecycleError> {
        let transfer_id = spec.transfer_id();
        let records =
            TransferJournal::decode_framed_records(transfer_id, framed, spec.max_journal_records)?;
        Self::replay(spec, authority, &records)
    }

    /// Cold-reads a persisted framed journal file and replays into a live coordinator.
    pub fn resume_from_journal_file(
        spec: TransferSpec,
        authority: AuthoritySnapshot,
        path: &std::path::Path,
    ) -> Result<Self, AtpLifecycleError> {
        let transfer_id = spec.transfer_id();
        let records =
            TransferJournal::read_framed_file(transfer_id, path, spec.max_journal_records)?;
        Self::replay(spec, authority, &records)
    }

    /// Builds a strict `schemas/transfer_receipt.v1.json`-conformant JSON document carrying
    /// exact timestamps derived from this coordinator's append-only journal.
    pub fn to_transfer_receipt_v1_json(
        &self,
        require_committed: bool,
        error_id: Option<&str>,
    ) -> Result<String, AtpLifecycleError> {
        if let Some(eid) = error_id
            && (eid.is_empty() || eid.len() > MAX_ID_LABEL_BYTES)
        {
            return Err(AtpLifecycleError::InvalidInput(format!(
                "error_id length must be within 1..={MAX_ID_LABEL_BYTES}"
            )));
        }
        let receipt = self.build_receipt(require_committed)?;
        let mut timestamps: Vec<(&str, i128)> = Vec::new();
        if let Some(first) = self.journal.records().first() {
            timestamps.push(("firstEventNs", first.timestamp_ns.0));
        }
        if let Some(last) = self.last_timestamp_ns {
            timestamps.push(("lastEventNs", last.0));
        }
        Ok(receipt.to_transfer_receipt_v1_json(&timestamps, error_id))
    }

    /// Deterministic transfer identity.
    #[must_use]
    pub const fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    /// Immutable transfer specification.
    #[must_use]
    pub const fn spec(&self) -> &TransferSpec {
        &self.spec
    }

    /// Current semantic transfer state.
    #[must_use]
    pub const fn semantic_state(&self) -> SemanticTransferState {
        self.semantic_state
    }

    /// Current archive publication state (if archive mode is enabled).
    #[must_use]
    pub const fn archive_state(&self) -> Option<ArchivePublicationState> {
        self.archive_state
    }

    /// Currently active publication/lease fence.
    #[must_use]
    pub const fn active_fence(&self) -> u64 {
        self.active_fence
    }

    /// Current authority snapshot.
    #[must_use]
    pub const fn authority(&self) -> &AuthoritySnapshot {
        &self.authority
    }

    /// Updates live authority/privacy/generation state (e.g., mid-transfer revocation).
    pub fn update_authority(&mut self, next: AuthoritySnapshot) {
        self.authority = next;
    }

    /// Non-collapsed transfer counters.
    #[must_use]
    pub const fn counters(&self) -> &TransferCounters {
        &self.counters
    }

    /// All tracked child records in canonical digest order.
    #[must_use]
    pub const fn children(&self) -> &BTreeMap<ContentDigest, ChildTransferRecord> {
        &self.children
    }

    /// All tracked path records in canonical path-id order.
    #[must_use]
    pub const fn paths(&self) -> &BTreeMap<String, PathRecord> {
        &self.paths
    }

    /// Ordered history of semantic transfer states.
    #[must_use]
    pub fn semantic_history(&self) -> &[SemanticTransferState] {
        &self.semantic_history
    }

    /// Ordered history of archive publication states.
    #[must_use]
    pub fn archive_history(&self) -> &[ArchivePublicationState] {
        &self.archive_history
    }

    /// Append-only checksummed journal.
    #[must_use]
    pub const fn journal(&self) -> &TransferJournal {
        &self.journal
    }

    /// Active reconciliation obligation when `Indeterminate`.
    #[must_use]
    pub const fn reconciliation_obligation(&self) -> Option<&IndeterminateTransferObligation> {
        self.reconciliation_obligation.as_ref()
    }

    /// Witnessed proof of retrievability, if recorded.
    #[must_use]
    pub const fn proof_of_retrievability(&self) -> Option<&ProofOfRetrievability> {
        self.proof_of_retrievability.as_ref()
    }

    /// Observed bytes charged across all transitions.
    #[must_use]
    pub const fn bytes_spent(&self) -> u64 {
        self.bytes_spent
    }

    /// Observed operations charged across all transitions.
    #[must_use]
    pub const fn ops_spent(&self) -> u64 {
        self.ops_spent
    }

    /// True if cooperative cancellation has been requested.
    #[must_use]
    pub const fn is_cancel_requested(&self) -> bool {
        self.cancel_requested
    }

    /// Core deterministic transition reducer. Applies one typed [`LifecycleEvent`] under `fence`,
    /// checks all invariants atomically before mutating state, and appends one sealed
    /// [`JournalRecord`].
    pub fn apply_event(
        &mut self,
        fence: u64,
        timestamp_ns: TimestampNs,
        event: LifecycleEvent,
        work_bytes: u64,
        work_ops: u64,
    ) -> Result<JournalRecord, AtpLifecycleError> {
        if fence < self.active_fence {
            return Err(AtpLifecycleError::StaleFence {
                active: self.active_fence,
                supplied: fence,
            });
        }
        if let Some(prev_ts) = self.last_timestamp_ns
            && timestamp_ns < prev_ts
        {
            return Err(AtpLifecycleError::ClockRewind {
                previous: prev_ts,
                supplied: timestamp_ns,
            });
        }

        // Charge work against authority budgets (cancellation/draining/indeterminate/rejection
        // cleanup transitions are still bounded by checked arithmetic and journal cap, while
        // forward progress enforces live budget & authority).
        let new_bytes =
            self.bytes_spent
                .checked_add(work_bytes)
                .ok_or(AtpLifecycleError::BudgetExhausted {
                    resource: "bytes_overflow",
                    spent: self.bytes_spent,
                    limit: self.authority.max_bytes_budget,
                })?;
        let new_ops =
            self.ops_spent
                .checked_add(work_ops)
                .ok_or(AtpLifecycleError::BudgetExhausted {
                    resource: "ops_overflow",
                    spent: self.ops_spent,
                    limit: self.authority.max_ops_budget,
                })?;

        let requires_live_authority = !matches!(
            event,
            LifecycleEvent::RequestCancel { .. }
                | LifecycleEvent::PathWorkDelta { .. }
                | LifecycleEvent::PathTransition {
                    to: PathState::Draining | PathState::Closed | PathState::Suspect,
                    ..
                }
                | LifecycleEvent::FinalizeCancel { .. }
                | LifecycleEvent::Reject { .. }
                | LifecycleEvent::Quarantine { .. }
                | LifecycleEvent::FailArchive { .. }
                | LifecycleEvent::MarkIndeterminate { .. }
        );
        if requires_live_authority {
            self.authority.validate_active(&self.spec)?;
            if new_bytes > self.authority.max_bytes_budget {
                return Err(AtpLifecycleError::BudgetExhausted {
                    resource: "bytes",
                    spent: new_bytes,
                    limit: self.authority.max_bytes_budget,
                });
            }
            if new_ops > self.authority.max_ops_budget {
                return Err(AtpLifecycleError::BudgetExhausted {
                    resource: "ops",
                    spent: new_ops,
                    limit: self.authority.max_ops_budget,
                });
            }
        }

        // Validate and stage state changes on a scratch clone so ANY error leaves `self`
        // completely unchanged (atomic transition semantics).
        let mut next = self.clone();
        next.apply_event_unchecked(fence, timestamp_ns, &event, new_bytes, new_ops)?;
        let record = next
            .journal
            .append(fence, timestamp_ns, event, work_bytes, work_ops)?;
        *self = next;
        Ok(record)
    }

    fn apply_event_unchecked(
        &mut self,
        fence: u64,
        timestamp_ns: TimestampNs,
        event: &LifecycleEvent,
        new_bytes: u64,
        new_ops: u64,
    ) -> Result<(), AtpLifecycleError> {
        match event {
            LifecycleEvent::Reserve {
                reserved_bytes,
                reserved_ops,
            } => {
                self.ensure_not_cancelling()?;
                if *reserved_bytes == 0 || *reserved_ops == 0 {
                    return Err(AtpLifecycleError::InvalidInput(
                        "reservation must declare nonzero bytes and ops".to_owned(),
                    ));
                }
                if *reserved_bytes > self.authority.max_bytes_budget {
                    return Err(AtpLifecycleError::BudgetExhausted {
                        resource: "reserved_bytes",
                        spent: *reserved_bytes,
                        limit: self.authority.max_bytes_budget,
                    });
                }
                if *reserved_ops > self.authority.max_ops_budget {
                    return Err(AtpLifecycleError::BudgetExhausted {
                        resource: "reserved_ops",
                        spent: *reserved_ops,
                        limit: self.authority.max_ops_budget,
                    });
                }
                self.transition_semantic(SemanticTransferState::Reserved)?;
                if self.archive_state.is_some() {
                    self.transition_archive(ArchivePublicationState::Reserved)?;
                }
            }

            LifecycleEvent::VerifyManifest { manifest_root } => {
                self.ensure_not_cancelling()?;
                if *manifest_root != self.spec.manifest_root {
                    return Err(AtpLifecycleError::ManifestMismatch {
                        expected: self.spec.manifest_root,
                        supplied: *manifest_root,
                    });
                }
                self.require_archive_enabled()?;
                self.transition_archive(ArchivePublicationState::ManifestVerified)?;
            }

            LifecycleEvent::OfferGraph {
                offered_bytes,
                offered_objects,
            } => {
                self.ensure_not_cancelling()?;
                if *offered_objects as usize != self.children.len() {
                    return Err(AtpLifecycleError::InvalidInput(format!(
                        "offered_objects ({offered_objects}) must match manifest child count ({})",
                        self.children.len()
                    )));
                }
                if self.archive_state == Some(ArchivePublicationState::Reserved) {
                    return Err(AtpLifecycleError::SkippedTransition {
                        layer: LifecycleLayer::ArchivePublication,
                        from: ArchivePublicationState::Reserved.canonical_id(),
                        to: ArchivePublicationState::Fetching.canonical_id(),
                    });
                }
                self.transition_semantic(SemanticTransferState::Offered)?;
                self.counters.offered_bytes =
                    self.counters.offered_bytes.saturating_add(*offered_bytes);
                self.counters.offered_objects = self
                    .counters
                    .offered_objects
                    .saturating_add(*offered_objects);
                for child in self.children.values_mut() {
                    child.offered = true;
                }
            }

            LifecycleEvent::BeginReceiving => {
                self.ensure_not_cancelling()?;
                self.transition_semantic(SemanticTransferState::Receiving)?;
                if self.archive_state.is_some() {
                    self.transition_archive(ArchivePublicationState::Fetching)?;
                }
            }

            LifecycleEvent::PathDiscover {
                path_id,
                failure_domain,
            } => {
                self.ensure_not_cancelling()?;
                if path_id.is_empty()
                    || path_id.len() > MAX_ID_LABEL_BYTES
                    || failure_domain.is_empty()
                    || failure_domain.len() > MAX_LABEL_BYTES
                {
                    return Err(AtpLifecycleError::InvalidInput(
                        "path_id and failure_domain must be non-empty bounded strings".to_owned(),
                    ));
                }
                if self.paths.contains_key(path_id) {
                    return Err(AtpLifecycleError::DuplicatePath {
                        path_id: path_id.clone(),
                    });
                }
                if self.paths.len() >= MAX_TRANSFER_PATHS {
                    return Err(AtpLifecycleError::BudgetExhausted {
                        resource: "paths",
                        spent: (self.paths.len() + 1) as u64,
                        limit: MAX_TRANSFER_PATHS as u64,
                    });
                }
                self.paths.insert(
                    path_id.clone(),
                    PathRecord {
                        path_id: path_id.clone(),
                        state: PathState::Discover,
                        failure_domain: failure_domain.clone(),
                        in_flight_ops: 0,
                        live_buffers: 0,
                        open_handles: 0,
                        bytes_delivered: 0,
                        transitions: vec![PathState::Discover],
                    },
                );
            }

            LifecycleEvent::PathTransition {
                path_id,
                to,
                reason: _,
            } => {
                if self.cancel_requested
                    && !matches!(
                        to,
                        PathState::Draining | PathState::Closed | PathState::Suspect
                    )
                {
                    return Err(AtpLifecycleError::CancellationInProgress);
                }
                let path =
                    self.paths
                        .get_mut(path_id)
                        .ok_or_else(|| AtpLifecycleError::UnknownPath {
                            path_id: path_id.clone(),
                        })?;
                if !path.state.can_transition_to(*to) {
                    return Err(AtpLifecycleError::SkippedTransition {
                        layer: LifecycleLayer::Path,
                        from: path.state.canonical_id(),
                        to: to.canonical_id(),
                    });
                }
                if *to == PathState::Closed && path.live_work() > 0 {
                    return Err(AtpLifecycleError::PathCloseWithLiveWork {
                        path_id: path_id.clone(),
                        in_flight_ops: path.in_flight_ops,
                        live_buffers: path.live_buffers,
                        open_handles: path.open_handles,
                    });
                }
                path.state = *to;
                path.transitions.push(*to);
            }

            LifecycleEvent::PathWorkDelta {
                path_id,
                in_flight_ops,
                live_buffers,
                open_handles,
            } => {
                let path =
                    self.paths
                        .get_mut(path_id)
                        .ok_or_else(|| AtpLifecycleError::UnknownPath {
                            path_id: path_id.clone(),
                        })?;
                if path.state == PathState::Closed {
                    return Err(AtpLifecycleError::SkippedTransition {
                        layer: LifecycleLayer::Path,
                        from: PathState::Closed.canonical_id(),
                        to: PathState::Active.canonical_id(),
                    });
                }
                if self.cancel_requested
                    && (*in_flight_ops > path.in_flight_ops
                        || *live_buffers > path.live_buffers
                        || *open_handles > path.open_handles)
                {
                    return Err(AtpLifecycleError::CancellationInProgress);
                }
                path.in_flight_ops = *in_flight_ops;
                path.live_buffers = *live_buffers;
                path.open_handles = *open_handles;
            }

            LifecycleEvent::DeliverChild {
                path_id,
                child_digest,
                bytes,
                reused_existing,
            } => {
                self.ensure_not_cancelling()?;
                if self.semantic_state != SemanticTransferState::Receiving {
                    return Err(AtpLifecycleError::SkippedTransition {
                        layer: LifecycleLayer::SemanticTransfer,
                        from: self.semantic_state.canonical_id(),
                        to: SemanticTransferState::Receiving.canonical_id(),
                    });
                }
                let path =
                    self.paths
                        .get_mut(path_id)
                        .ok_or_else(|| AtpLifecycleError::UnknownPath {
                            path_id: path_id.clone(),
                        })?;
                if !path.state.can_expose_data() {
                    return Err(AtpLifecycleError::PathNotActive {
                        path_id: path_id.clone(),
                        state: path.state,
                    });
                }
                let child = self.children.get_mut(child_digest).ok_or(
                    AtpLifecycleError::UndeclaredChild {
                        child: *child_digest,
                    },
                )?;
                if child.verified || child.received_bytes >= child.expected_bytes {
                    // Duplicate delivery is strictly idempotent: never double-counts verified bytes.
                    self.counters.duplicate_offers_ignored =
                        self.counters.duplicate_offers_ignored.saturating_add(1);
                } else {
                    if *bytes > child.expected_bytes.saturating_sub(child.received_bytes) {
                        return Err(AtpLifecycleError::InvalidInput(format!(
                            "delivered bytes ({bytes}) exceed remaining expected bytes for child"
                        )));
                    }
                    child.received_bytes = child.received_bytes.saturating_add(*bytes);
                    path.bytes_delivered = path.bytes_delivered.saturating_add(*bytes);
                    if *reused_existing {
                        self.counters.reused_bytes =
                            self.counters.reused_bytes.saturating_add(*bytes);
                    } else {
                        self.counters.received_bytes =
                            self.counters.received_bytes.saturating_add(*bytes);
                    }
                    if child.archive_object_state.is_none() && self.archive_state.is_some() {
                        child.archive_object_state = Some(ArchiveObjectState::LocalStaged);
                    }
                }
            }

            LifecycleEvent::RepairChild {
                child_digest,
                reconstructed_digest,
                repair_symbols_used,
                bytes,
            } => {
                self.ensure_not_cancelling()?;
                if !matches!(
                    self.semantic_state,
                    SemanticTransferState::Receiving | SemanticTransferState::ChildrenVerified
                ) {
                    return Err(AtpLifecycleError::SkippedTransition {
                        layer: LifecycleLayer::SemanticTransfer,
                        from: self.semantic_state.canonical_id(),
                        to: SemanticTransferState::Receiving.canonical_id(),
                    });
                }
                let child = self.children.get_mut(child_digest).ok_or(
                    AtpLifecycleError::UndeclaredChild {
                        child: *child_digest,
                    },
                )?;
                if *repair_symbols_used == 0 {
                    return Err(AtpLifecycleError::InvalidInput(
                        "repair event must record at least one repair symbol".to_owned(),
                    ));
                }
                // XFER-INV-006: post-repair canonical digest MUST equal declared child digest.
                if *reconstructed_digest != child.digest {
                    return Err(AtpLifecycleError::RepairDigestMismatch {
                        expected: child.digest,
                        reconstructed: *reconstructed_digest,
                    });
                }
                if *bytes != child.expected_bytes {
                    return Err(AtpLifecycleError::RepairDigestMismatch {
                        expected: child.digest,
                        reconstructed: *reconstructed_digest,
                    });
                }
                child.repaired = true;
                child.post_repair_digest = Some(*reconstructed_digest);
                child.received_bytes = child.expected_bytes;
                self.counters.repair_symbols_used = self
                    .counters
                    .repair_symbols_used
                    .saturating_add(*repair_symbols_used);
                if child.archive_object_state.is_none() && self.archive_state.is_some() {
                    child.archive_object_state = Some(ArchiveObjectState::LocalStaged);
                }
            }

            LifecycleEvent::VerifyChild {
                child_digest,
                verified_bytes,
            } => {
                self.ensure_not_cancelling()?;
                if self.semantic_state != SemanticTransferState::Receiving {
                    return Err(AtpLifecycleError::SkippedTransition {
                        layer: LifecycleLayer::SemanticTransfer,
                        from: self.semantic_state.canonical_id(),
                        to: SemanticTransferState::ChildrenVerified.canonical_id(),
                    });
                }
                let child = self.children.get_mut(child_digest).ok_or(
                    AtpLifecycleError::UndeclaredChild {
                        child: *child_digest,
                    },
                )?;
                if *verified_bytes != child.expected_bytes
                    || child.received_bytes != child.expected_bytes
                {
                    return Err(AtpLifecycleError::RootBeforeChild {
                        child: *child_digest,
                        reason: "child bytes incomplete prior to verification".to_owned(),
                    });
                }
                if child.repaired && child.post_repair_digest != Some(child.digest) {
                    return Err(AtpLifecycleError::RepairDigestMismatch {
                        expected: child.digest,
                        reconstructed: child
                            .post_repair_digest
                            .unwrap_or_else(|| ContentDigest::sha256(b"missing-repair-digest")),
                    });
                }
                if !child.verified {
                    child.verified = true;
                    child.disposition = StagedChildDisposition::Verified;
                    self.counters.verified_bytes =
                        self.counters.verified_bytes.saturating_add(*verified_bytes);
                    self.counters.verified_objects =
                        self.counters.verified_objects.saturating_add(1);
                }
            }

            LifecycleEvent::AdvanceChildArchiveState { child_digest, to } => {
                self.ensure_not_cancelling()?;
                self.require_archive_enabled()?;
                let child = self.children.get_mut(child_digest).ok_or(
                    AtpLifecycleError::UndeclaredChild {
                        child: *child_digest,
                    },
                )?;
                match child.archive_object_state {
                    None if *to == ArchiveObjectState::LocalStaged => {
                        child.archive_object_state = Some(*to);
                    }
                    Some(current) if current.can_advance_to(*to) => {
                        if *to == ArchiveObjectState::RemoteChildrenVerified && !child.verified {
                            return Err(AtpLifecycleError::RootBeforeChild {
                                child: *child_digest,
                                reason: "cannot mark remote_children_verified before child digest verification".to_owned(),
                            });
                        }
                        child.archive_object_state = Some(*to);
                    }
                    Some(current) => {
                        return Err(AtpLifecycleError::SkippedTransition {
                            layer: LifecycleLayer::ArchiveObjectCustody,
                            from: current.canonical_id(),
                            to: to.canonical_id(),
                        });
                    }
                    None => {
                        return Err(AtpLifecycleError::SkippedTransition {
                            layer: LifecycleLayer::ArchiveObjectCustody,
                            from: "none",
                            to: to.canonical_id(),
                        });
                    }
                }
            }

            LifecycleEvent::MarkStaged => {
                self.ensure_not_cancelling()?;
                self.require_archive_enabled()?;
                for child in self.children.values() {
                    if child.received_bytes != child.expected_bytes {
                        return Err(AtpLifecycleError::RootBeforeChild {
                            child: child.digest,
                            reason: "cannot transition archive to Staged while child bytes are incomplete".to_owned(),
                        });
                    }
                }
                self.transition_archive(ArchivePublicationState::Staged)?;
            }

            LifecycleEvent::MarkChildrenVerified => {
                self.ensure_not_cancelling()?;
                self.ensure_all_children_verified()?;
                self.transition_semantic(SemanticTransferState::ChildrenVerified)?;
                if self.archive_state.is_some() {
                    self.transition_archive(ArchivePublicationState::ObjectVerified)?;
                }
            }

            LifecycleEvent::CloseGraph => {
                self.ensure_not_cancelling()?;
                self.ensure_all_children_verified()?;
                self.transition_semantic(SemanticTransferState::GraphClosed)?;
                if self.archive_state.is_some() {
                    self.transition_archive(ArchivePublicationState::GraphClosed)?;
                }
            }

            LifecycleEvent::SatisfyDurability { failure_domains } => {
                self.ensure_not_cancelling()?;
                self.ensure_all_children_verified()?;
                let unique: BTreeSet<String> = failure_domains
                    .iter()
                    .filter(|d| !d.is_empty() && d.len() <= MAX_LABEL_BYTES)
                    .cloned()
                    .collect();
                if unique.len() < self.spec.required_failure_domains as usize {
                    return Err(AtpLifecycleError::InsufficientFailureDomains {
                        required: self.spec.required_failure_domains,
                        observed: unique.len() as u32,
                    });
                }
                self.transition_semantic(SemanticTransferState::DurabilitySatisfied)?;
                self.verified_failure_domains = unique;
            }

            LifecycleEvent::MarkExposureReady { policy_epoch } => {
                self.ensure_not_cancelling()?;
                self.require_archive_enabled()?;
                self.ensure_all_children_verified()?;
                if *policy_epoch != self.authority.privacy_epoch {
                    return Err(AtpLifecycleError::StaleAnchorOrGeneration {
                        reason: format!(
                            "exposure policy_epoch ({policy_epoch}) differs from current privacy_epoch ({})",
                            self.authority.privacy_epoch
                        ),
                    });
                }
                self.transition_archive(ArchivePublicationState::ExposureReady)?;
            }

            LifecycleEvent::AdvanceFence { new_fence } => {
                if *new_fence <= self.active_fence {
                    return Err(AtpLifecycleError::StaleFence {
                        active: self.active_fence,
                        supplied: *new_fence,
                    });
                }
                self.active_fence = *new_fence;
            }

            LifecycleEvent::CommitRoot {
                root_digest,
                commit_anchor,
            } => {
                self.ensure_not_cancelling()?;
                if *root_digest != self.spec.manifest_root {
                    return Err(AtpLifecycleError::ManifestMismatch {
                        expected: self.spec.manifest_root,
                        supplied: *root_digest,
                    });
                }
                self.ensure_all_children_verified()?;
                self.transition_semantic(SemanticTransferState::RootCommitted)?;
                self.commit_anchor = Some(*commit_anchor);
                for child in self.children.values_mut() {
                    child.disposition = StagedChildDisposition::Committed;
                }
                self.counters.committed_bytes = self.counters.verified_bytes;
                self.counters.committed_objects = self.children.len() as u64;
            }

            LifecycleEvent::PublishArchiveRoot {
                root_digest,
                provider_tuple,
            } => {
                self.ensure_not_cancelling()?;
                self.require_archive_enabled()?;
                if *root_digest != self.spec.manifest_root {
                    return Err(AtpLifecycleError::ManifestMismatch {
                        expected: self.spec.manifest_root,
                        supplied: *root_digest,
                    });
                }
                if provider_tuple.is_empty() || provider_tuple.len() > MAX_LABEL_BYTES {
                    return Err(AtpLifecycleError::InvalidInput(
                        "provider_tuple must be a non-empty bounded string".to_owned(),
                    ));
                }
                self.ensure_all_children_verified()?;
                if !matches!(
                    self.semantic_state,
                    SemanticTransferState::DurabilitySatisfied
                        | SemanticTransferState::RootCommitted
                ) {
                    return Err(AtpLifecycleError::InvalidInput(
                        "archive publication requires the configured transfer durability"
                            .to_owned(),
                    ));
                }
                // Root publication is strictly last: every child in archive mode must already be
                // at least remote_children_verified when archive object custody is tracked.
                for child in self.children.values() {
                    if let Some(state) = child.archive_object_state
                        && state < ArchiveObjectState::RemoteChildrenVerified
                    {
                        return Err(AtpLifecycleError::RootBeforeChild {
                            child: child.digest,
                            reason: format!(
                                "child archive custody state '{}' is below remote_children_verified",
                                state.canonical_id()
                            ),
                        });
                    }
                }
                self.transition_archive(ArchivePublicationState::RootPublished)?;
                self.provider_tuple = Some(provider_tuple.clone());
            }

            LifecycleEvent::QualifyReplicas { failure_domains } => {
                self.ensure_not_cancelling()?;
                self.require_archive_enabled()?;
                let unique: BTreeSet<String> = failure_domains
                    .iter()
                    .filter(|d| !d.is_empty() && d.len() <= MAX_LABEL_BYTES)
                    .cloned()
                    .collect();
                if unique.len() < self.spec.required_failure_domains as usize {
                    return Err(AtpLifecycleError::InsufficientFailureDomains {
                        required: self.spec.required_failure_domains,
                        observed: unique.len() as u32,
                    });
                }
                self.transition_archive(ArchivePublicationState::ReplicaQualified)?;
                self.verified_failure_domains = unique;
            }

            LifecycleEvent::VerifyRetrievability { proof } => {
                self.ensure_not_cancelling()?;
                self.require_archive_enabled()?;
                proof.validate_for(self.spec.manifest_root)?;
                self.transition_archive(ArchivePublicationState::RetrievabilityVerified)?;
                if self.commit_anchor.is_none() {
                    return Err(AtpLifecycleError::InvalidInput(
                        "retrievability requires committed root reachability".to_owned(),
                    ));
                }
                if !self
                    .verified_failure_domains
                    .contains(&proof.failure_domain)
                {
                    return Err(AtpLifecycleError::InvalidInput(
                        "retrievability sample must come from a qualified replica domain"
                            .to_owned(),
                    ));
                }
                // Remote publication and ledger commit may occur in either order. A sample
                // attests to the reachable archive only after both milestones are recorded.
                let last_root_event = self.journal.records().iter().rev().find(|record| {
                    matches!(
                        record.event,
                        LifecycleEvent::CommitRoot { .. }
                            | LifecycleEvent::PublishArchiveRoot { .. }
                    )
                });
                if last_root_event.is_none_or(|record| proof.sampled_at < record.timestamp_ns)
                    || proof.sampled_at > timestamp_ns
                {
                    return Err(AtpLifecycleError::InvalidInput(
                        "retrievability sample falls outside the published and committed interval"
                            .to_owned(),
                    ));
                }
                self.proof_of_retrievability = Some(proof.clone());
            }

            LifecycleEvent::CompleteArchive => {
                self.ensure_not_cancelling()?;
                self.require_archive_enabled()?;
                if self.archive_state != Some(ArchivePublicationState::RetrievabilityVerified)
                    || self.proof_of_retrievability.is_none()
                {
                    return Err(AtpLifecycleError::ArchiveCompleteWithoutRetrievability {
                        current: self
                            .archive_state
                            .unwrap_or(ArchivePublicationState::Planned),
                    });
                }
                self.transition_archive(ArchivePublicationState::Complete)?;
            }

            LifecycleEvent::ScrubArchive { scrub_digest: _ } => {
                self.require_archive_enabled()?;
                self.transition_archive(ArchivePublicationState::Scrubbed)?;
            }

            LifecycleEvent::RetireArchive { deletion_proof: _ } => {
                self.require_archive_enabled()?;
                self.transition_archive(ArchivePublicationState::Retired)?;
            }

            LifecycleEvent::SealReceipt { receipt_digest } => {
                if self.semantic_state != SemanticTransferState::RootCommitted {
                    return Err(AtpLifecycleError::ReceiptBeforeCommit {
                        semantic: self.semantic_state,
                        archive: self.archive_state,
                    });
                }
                let expected = self.build_receipt(true)?.receipt_digest;
                if *receipt_digest != expected {
                    return Err(AtpLifecycleError::InvalidInput(
                        "seal digest differs from the committed receipt at this journal head"
                            .to_owned(),
                    ));
                }
                self.transition_semantic(SemanticTransferState::ReceiptSealed)?;
            }

            LifecycleEvent::Supersede {
                successor_transfer_id,
            } => {
                if *successor_transfer_id == self.transfer_id {
                    return Err(AtpLifecycleError::InvalidInput(
                        "transfer cannot supersede itself".to_owned(),
                    ));
                }
                self.transition_semantic(SemanticTransferState::Superseded)?;
            }

            LifecycleEvent::Reject { reason } => {
                if reason.is_empty() || reason.len() > MAX_LABEL_BYTES {
                    return Err(AtpLifecycleError::InvalidInput(
                        "rejection reason must be non-empty".to_owned(),
                    ));
                }
                self.transition_semantic(SemanticTransferState::Rejected)?;
                if let Some(arch) = self.archive_state
                    && !arch.is_terminal()
                {
                    self.transition_archive(ArchivePublicationState::Failed)?;
                }
                self.terminal_reason = Some(reason.clone());
            }

            LifecycleEvent::Quarantine {
                reason,
                affected_children,
            } => {
                if reason.is_empty() || reason.len() > MAX_LABEL_BYTES {
                    return Err(AtpLifecycleError::InvalidInput(
                        "quarantine reason must be non-empty".to_owned(),
                    ));
                }
                let mut transitioned = false;
                if !self.semantic_state.is_terminal()
                    && self
                        .semantic_state
                        .can_transition_to(SemanticTransferState::Quarantined)
                {
                    self.transition_semantic(SemanticTransferState::Quarantined)?;
                    transitioned = true;
                }
                if let Some(arch) = self.archive_state
                    && !arch.is_terminal()
                {
                    self.transition_archive(ArchivePublicationState::Quarantined)?;
                    transitioned = true;
                }
                if !transitioned {
                    return Err(AtpLifecycleError::SkippedTransition {
                        layer: LifecycleLayer::SemanticTransfer,
                        from: self.semantic_state.canonical_id(),
                        to: SemanticTransferState::Quarantined.canonical_id(),
                    });
                }
                for digest in affected_children {
                    let child = self
                        .children
                        .get_mut(digest)
                        .ok_or(AtpLifecycleError::UndeclaredChild { child: *digest })?;
                    child.disposition = StagedChildDisposition::Quarantined;
                    child.verified = false;
                }
                self.terminal_reason = Some(reason.clone());
            }

            LifecycleEvent::RequestCancel { reason } => {
                if reason.is_empty() || reason.len() > MAX_LABEL_BYTES {
                    return Err(AtpLifecycleError::InvalidInput(
                        "cancel reason must be non-empty".to_owned(),
                    ));
                }
                if self.semantic_state == SemanticTransferState::RootCommitted
                    || self.semantic_state.is_terminal()
                {
                    return Err(AtpLifecycleError::SkippedTransition {
                        layer: LifecycleLayer::SemanticTransfer,
                        from: self.semantic_state.canonical_id(),
                        to: SemanticTransferState::Aborted.canonical_id(),
                    });
                }
                self.cancel_requested = true;
                self.cancel_reason = Some(reason.clone());
            }

            LifecycleEvent::FinalizeCancel { child_dispositions } => {
                if !self.cancel_requested {
                    return Err(AtpLifecycleError::InvalidInput(
                        "FinalizeCancel requires a prior RequestCancel".to_owned(),
                    ));
                }
                // XFER-INV-008: every path MUST be Closed with zero live work before finalizing.
                for path in self.paths.values() {
                    if path.state != PathState::Closed {
                        return Err(AtpLifecycleError::ActivePathsRemaining {
                            path_id: path.path_id.clone(),
                            state: path.state,
                            live_work: path.live_work(),
                        });
                    }
                    if path.live_work() > 0 {
                        return Err(AtpLifecycleError::PathCloseWithLiveWork {
                            path_id: path.path_id.clone(),
                            in_flight_ops: path.in_flight_ops,
                            live_buffers: path.live_buffers,
                            open_handles: path.open_handles,
                        });
                    }
                }
                // Every declared child must receive an explicit non-Pending/non-Committed
                // post-cancellation classification (Reusable, Quarantined, or Collectable).
                let mut seen = BTreeSet::new();
                for (digest, disp) in child_dispositions {
                    if !matches!(
                        disp,
                        StagedChildDisposition::Reusable
                            | StagedChildDisposition::Quarantined
                            | StagedChildDisposition::Collectable
                    ) {
                        return Err(AtpLifecycleError::InvalidInput(
                            "cancellation child disposition must be Reusable, Quarantined, or Collectable".to_owned(),
                        ));
                    }
                    let child = self
                        .children
                        .get_mut(digest)
                        .ok_or(AtpLifecycleError::UndeclaredChild { child: *digest })?;
                    if *disp == StagedChildDisposition::Reusable && !child.verified {
                        return Err(AtpLifecycleError::InvalidInput(
                            "unverified child cannot be classified Reusable".to_owned(),
                        ));
                    }
                    child.disposition = *disp;
                    seen.insert(*digest);
                }
                if seen.len() != self.children.len() {
                    return Err(AtpLifecycleError::InvalidInput(format!(
                        "FinalizeCancel must classify all {} children (classified {})",
                        self.children.len(),
                        seen.len()
                    )));
                }
                self.transition_semantic(SemanticTransferState::Aborted)?;
                if let Some(arch) = self.archive_state
                    && !arch.is_terminal()
                {
                    self.transition_archive(ArchivePublicationState::Cancelled)?;
                }
                self.terminal_reason = self.cancel_reason.clone();
            }

            LifecycleEvent::FailArchive { reason } => {
                self.require_archive_enabled()?;
                if reason.is_empty() || reason.len() > MAX_LABEL_BYTES {
                    return Err(AtpLifecycleError::InvalidInput(
                        "archive failure reason must be non-empty".to_owned(),
                    ));
                }
                self.transition_archive(ArchivePublicationState::Failed)?;
                self.terminal_reason = Some(reason.clone());
            }

            LifecycleEvent::MarkIndeterminate {
                obligation,
                archive_state_affected,
            } => {
                obligation.validate_for(self.transfer_id, fence)?;
                if *archive_state_affected {
                    self.require_archive_enabled()?;
                    self.transition_archive(ArchivePublicationState::Indeterminate)?;
                }
                if self
                    .semantic_state
                    .can_transition_to(SemanticTransferState::Indeterminate)
                {
                    self.transition_semantic(SemanticTransferState::Indeterminate)?;
                } else if !*archive_state_affected {
                    return Err(AtpLifecycleError::SkippedTransition {
                        layer: LifecycleLayer::SemanticTransfer,
                        from: self.semantic_state.canonical_id(),
                        to: SemanticTransferState::Indeterminate.canonical_id(),
                    });
                }
                self.reconciliation_obligation = Some(obligation.clone());
                self.terminal_reason = Some(obligation.reason.clone());
            }
        }

        self.bytes_spent = new_bytes;
        self.ops_spent = new_ops;
        self.last_timestamp_ns = Some(timestamp_ns);
        Ok(())
    }

    /// Produces a sealed canonical [`LifecycleReceipt`] for the current state.
    ///
    /// When `require_committed` is `true`, refuses with [`AtpLifecycleError::ReceiptBeforeCommit`]
    /// unless the semantic layer has reached `RootCommitted` or `ReceiptSealed` (and in archive
    /// mode, `RootPublished` or later).
    pub fn build_receipt(
        &self,
        require_committed: bool,
    ) -> Result<LifecycleReceipt, AtpLifecycleError> {
        if require_committed {
            let semantic_ok = matches!(
                self.semantic_state,
                SemanticTransferState::RootCommitted
                    | SemanticTransferState::ReceiptSealed
                    | SemanticTransferState::Superseded
            );
            let archive_ok = self
                .archive_state
                .is_none_or(archive_state_allows_committed_receipt);
            if !semantic_ok || !archive_ok {
                return Err(AtpLifecycleError::ReceiptBeforeCommit {
                    semantic: self.semantic_state,
                    archive: self.archive_state,
                });
            }
        }

        let staged_child_dispositions: Vec<(ContentDigest, StagedChildDisposition)> = self
            .children
            .values()
            .map(|c| (c.digest, c.disposition))
            .collect();
        let path_states: Vec<(String, PathState, u64)> = self
            .paths
            .values()
            .map(|p| (p.path_id.clone(), p.state, p.live_work()))
            .collect();
        let failure_domains: Vec<String> = self.verified_failure_domains.iter().cloned().collect();

        let mut receipt = LifecycleReceipt {
            transfer_id: self.transfer_id,
            root_digest: self.spec.manifest_root,
            source: self.spec.sender.clone(),
            destination: self.spec.receiver.clone(),
            contract_basis_digest: self.spec.contract_basis_digest,
            authority_generation: self.authority.authority_generation,
            publication_fence: self.active_fence,
            semantic_state: self.semantic_state,
            archive_state: self.archive_state,
            semantic_transitions: self.semantic_history.clone(),
            archive_transitions: self.archive_history.clone(),
            path_states,
            counters: self.counters,
            failure_domains,
            provider_tuple: self.provider_tuple.clone(),
            commit_anchor: self.commit_anchor,
            proof_of_retrievability_digest: self
                .proof_of_retrievability
                .as_ref()
                .map(ProofOfRetrievability::digest),
            journal_head_digest: self.journal.head_digest(),
            journal_record_count: self.journal.records().len() as u64,
            bytes_spent: self.bytes_spent,
            ops_spent: self.ops_spent,
            staged_child_dispositions,
            reconciliation_obligation: self.reconciliation_obligation.clone(),
            terminal_reason: self.terminal_reason.clone(),
            receipt_digest: ContentDigest::sha256(b"unsealed-receipt"),
        };
        receipt.receipt_digest = receipt.compute_digest();
        Ok(receipt)
    }

    fn ensure_not_cancelling(&self) -> Result<(), AtpLifecycleError> {
        if self.cancel_requested {
            return Err(AtpLifecycleError::CancellationInProgress);
        }
        Ok(())
    }

    fn require_archive_enabled(&self) -> Result<(), AtpLifecycleError> {
        if self.archive_state.is_none() {
            return Err(AtpLifecycleError::InvalidInput(
                "archive transition attempted on non-archive transfer".to_owned(),
            ));
        }
        Ok(())
    }

    fn ensure_all_children_verified(&self) -> Result<(), AtpLifecycleError> {
        for child in self.children.values() {
            if !child.verified {
                return Err(AtpLifecycleError::RootBeforeChild {
                    child: child.digest,
                    reason: "declared manifest child is not yet verified".to_owned(),
                });
            }
            if child.repaired && child.post_repair_digest != Some(child.digest) {
                return Err(AtpLifecycleError::RepairDigestMismatch {
                    expected: child.digest,
                    reconstructed: child
                        .post_repair_digest
                        .unwrap_or_else(|| ContentDigest::sha256(b"missing-repair-digest")),
                });
            }
        }
        Ok(())
    }

    fn transition_semantic(
        &mut self,
        next: SemanticTransferState,
    ) -> Result<(), AtpLifecycleError> {
        if !self.semantic_state.can_transition_to(next) {
            return Err(AtpLifecycleError::SkippedTransition {
                layer: LifecycleLayer::SemanticTransfer,
                from: self.semantic_state.canonical_id(),
                to: next.canonical_id(),
            });
        }
        self.semantic_state = next;
        self.semantic_history.push(next);
        Ok(())
    }

    fn transition_archive(
        &mut self,
        next: ArchivePublicationState,
    ) -> Result<(), AtpLifecycleError> {
        let Some(current) = self.archive_state else {
            return Err(AtpLifecycleError::InvalidInput(
                "archive layer not enabled".to_owned(),
            ));
        };
        if !current.can_transition_to(next) {
            return Err(AtpLifecycleError::SkippedTransition {
                layer: LifecycleLayer::ArchivePublication,
                from: current.canonical_id(),
                to: next.canonical_id(),
            });
        }
        self.archive_state = Some(next);
        self.archive_history.push(next);
        Ok(())
    }
}

impl TransferSpec {
    /// Validates hard bounds, critical extensions, format version, and unique non-empty children.
    pub fn validate(&self) -> Result<(), AtpLifecycleError> {
        if self.protocol_generation == 0 {
            return Err(AtpLifecycleError::IncompatibleVersion {
                reason: "protocol_generation must be >= 1".to_owned(),
            });
        }
        if self.format_version != ATP_LIFECYCLE_FORMAT_VERSION {
            return Err(AtpLifecycleError::IncompatibleVersion {
                reason: format!(
                    "unsupported format_version {}; expected {ATP_LIFECYCLE_FORMAT_VERSION}",
                    self.format_version
                ),
            });
        }
        if self.unknown_critical_extensions.len() > MAX_CRITICAL_EXTENSIONS {
            return Err(AtpLifecycleError::IncompatibleVersion {
                reason: "critical extension count exceeds hard bound".to_owned(),
            });
        }
        if let Some(ext) = self.unknown_critical_extensions.first() {
            return Err(AtpLifecycleError::UnknownCriticalExtension {
                extension: ext.clone(),
            });
        }
        if self.sender.is_empty()
            || self.sender.len() > MAX_LABEL_BYTES
            || self.receiver.is_empty()
            || self.receiver.len() > MAX_LABEL_BYTES
        {
            return Err(AtpLifecycleError::InvalidInput(
                "sender and receiver identities must be non-empty bounded strings".to_owned(),
            ));
        }
        if self.expected_children.is_empty() || self.expected_children.len() > MAX_TRANSFER_CHILDREN
        {
            return Err(AtpLifecycleError::InvalidInput(format!(
                "expected_children count ({}) must be within 1..={MAX_TRANSFER_CHILDREN}",
                self.expected_children.len()
            )));
        }
        let mut seen = BTreeSet::new();
        for &(digest, bytes) in &self.expected_children {
            if bytes == 0 {
                return Err(AtpLifecycleError::InvalidInput(
                    "declared child byte length must be > 0".to_owned(),
                ));
            }
            if !seen.insert(digest) {
                return Err(AtpLifecycleError::InvalidInput(
                    "duplicate child digest in TransferSpec".to_owned(),
                ));
            }
        }
        if self.required_failure_domains == 0
            || self.required_failure_domains as usize > MAX_FAILURE_DOMAINS
        {
            return Err(AtpLifecycleError::InvalidInput(format!(
                "required_failure_domains ({}) must be within 1..={MAX_FAILURE_DOMAINS}",
                self.required_failure_domains
            )));
        }
        Ok(())
    }
}

impl LifecycleReceipt {
    /// Computes the canonical SHA-256 receipt digest (`fss.atp_lifecycle_receipt.v1`).
    #[must_use]
    pub fn compute_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text(ATP_LIFECYCLE_RECEIPT_DOMAIN);
        enc.digest(self.transfer_id.digest());
        enc.digest(self.root_digest);
        enc.text(&self.source);
        enc.text(&self.destination);
        enc.digest(self.contract_basis_digest);
        enc.u64(self.authority_generation);
        enc.u64(self.publication_fence);
        enc.text(self.semantic_state.canonical_id());
        match self.archive_state {
            Some(a) => {
                enc.bool(true);
                enc.text(a.canonical_id());
            }
            None => enc.bool(false),
        }
        enc.u64(self.semantic_transitions.len() as u64);
        for s in &self.semantic_transitions {
            enc.text(s.canonical_id());
        }
        enc.u64(self.archive_transitions.len() as u64);
        for a in &self.archive_transitions {
            enc.text(a.canonical_id());
        }
        enc.u64(self.path_states.len() as u64);
        for (pid, st, work) in &self.path_states {
            enc.text(pid);
            enc.text(st.canonical_id());
            enc.u64(*work);
        }
        enc.u64(self.counters.offered_bytes);
        enc.u64(self.counters.received_bytes);
        enc.u64(self.counters.verified_bytes);
        enc.u64(self.counters.committed_bytes);
        enc.u64(self.counters.reused_bytes);
        enc.u64(self.counters.offered_objects);
        enc.u64(self.counters.verified_objects);
        enc.u64(self.counters.committed_objects);
        enc.u64(self.counters.repair_symbols_used);
        enc.u64(self.counters.duplicate_offers_ignored);
        enc.u64(self.failure_domains.len() as u64);
        for fd in &self.failure_domains {
            enc.text(fd);
        }
        match &self.provider_tuple {
            Some(pt) => {
                enc.bool(true);
                enc.text(pt);
            }
            None => enc.bool(false),
        }
        match self.commit_anchor {
            Some(anchor) => {
                enc.bool(true);
                enc.digest(anchor);
            }
            None => enc.bool(false),
        }
        match self.proof_of_retrievability_digest {
            Some(por) => {
                enc.bool(true);
                enc.digest(por);
            }
            None => enc.bool(false),
        }
        match self.journal_head_digest {
            Some(jh) => {
                enc.bool(true);
                enc.digest(jh);
            }
            None => enc.bool(false),
        }
        enc.u64(self.journal_record_count);
        enc.u64(self.bytes_spent);
        enc.u64(self.ops_spent);
        enc.u64(self.staged_child_dispositions.len() as u64);
        for (d, disp) in &self.staged_child_dispositions {
            enc.digest(*d);
            enc.text(disp.as_str());
        }
        match &self.reconciliation_obligation {
            Some(ob) => {
                enc.bool(true);
                enc.text(&ob.obligation_id);
                enc.u64(ob.fence);
                enc.digest(ob.follow_up_digest);
            }
            None => enc.bool(false),
        }
        match &self.terminal_reason {
            Some(r) => {
                enc.bool(true);
                enc.text(r);
            }
            None => enc.bool(false),
        }
        ContentDigest::sha256(&enc.finish())
    }
}
