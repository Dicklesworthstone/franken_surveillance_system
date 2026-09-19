#![forbid(unsafe_code)]
//! Event evidence graph and revision store (FSS-081).
//!
//! Provides an append-only, deterministic event evidence graph and revision store:
//! - All state transitions are append-only commits pinned to an immutable basis `LedgerAnchor`.
//! - Revisions never rewrite history; corrections supersede earlier revisions.
//! - Derived state (lineages, graph index, contradictions, unresolved worlds) is fully
//!   rebuildable from canonical history.
//! - Contradictions and unresolved worlds remain first-class and cannot be pruned by ranking.
//! - Reads outside certified coverage return typed `NotObservable` states, never absence.
//! - Hard size and capacity bounds, tested at exact bound and bound+1.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::belief::{BeliefError, Contradiction};
use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::{Completeness, ContractError};
use crate::digest::ContentDigest;
use crate::event::{
    EventDecodeError, EventHypothesis, EventLineage, EventState, EventTransitionError,
    EventTransitionParams, EvidenceGraph, MAX_LINEAGE_DEPTH,
};
use crate::evidence::{CoverageContinuity, CoverageStopReason, CoverageWitness, LedgerAnchor};
use crate::ids::EventId;
use crate::time::TimestampNs;

/// Maximum number of distinct events retained in one store instance.
pub const MAX_STORE_EVENTS: usize = 10_000;

/// Maximum number of commits retained in one store instance history.
pub const MAX_STORE_COMMITS: usize = 100_000;

/// Maximum lineage depth (number of revisions per event).
pub const MAX_STORE_LINEAGE_DEPTH: usize = MAX_LINEAGE_DEPTH;

/// Maximum number of evidence graphs attached to a single revision.
pub const MAX_GRAPHS_PER_REVISION: usize = 64;

/// Maximum number of first-class contradictions recorded against a single event.
pub const MAX_CONTRADICTIONS_PER_EVENT: usize = 64;

/// Maximum number of coverage witnesses registered in one store instance.
///
/// Reaching this bound (or [`MAX_STORE_COMMITS`]) is fail-closed for every coverage-for-absence
/// evaluation, not only for the domains a refused witness named. Once the store is at capacity a
/// later witness, possibly one reporting a coverage gap, can no longer be admitted, so no domain's
/// absence can be certified: every evaluation carries
/// [`NotObservableReason::CoverageRegistryCapacityExceeded`]. The at-capacity state is derived only
/// from history-backed contents (see [`EventRevisionStore::coverage_registry_at_capacity`]), so a
/// store rebuilt from canonical history evaluates identically to the live one. Per-domain
/// refusal tracking is deliberately not kept: it lived outside canonical history, could not be
/// rebuilt, and needed its own bound whose saturation failed open.
pub const MAX_STORE_COVERAGE_WITNESSES: usize = 1_024;

/// Canonical digest domain for event store commits.
pub const EVENT_STORE_COMMIT_DOMAIN: &str = "fss.event_store_commit.v1";

/// Canonical digest domain for event store state roots.
pub const EVENT_STORE_STATE_DOMAIN: &str = "fss.event_store_state.v1";

/// Typed error conditions for event revision store operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventStoreError {
    /// Commit attempted against a stale or non-matching basis anchor.
    StaleAnchor {
        /// Expected basis anchor.
        expected: Box<LedgerAnchor>,
        /// Actual anchor provided by caller.
        actual: Box<LedgerAnchor>,
    },
    /// Event lineage depth strictly exceeds hard bound.
    LineageDepthExceeded {
        /// Event identifier.
        event_id: EventId,
        /// Configured maximum depth.
        limit: usize,
        /// Actual attempted depth.
        actual: usize,
    },
    /// Total events count strictly exceeds store capacity bound.
    StoreEventCapacityExceeded {
        /// Configured maximum events.
        limit: usize,
        /// Actual attempted count.
        actual: usize,
    },
    /// Total commits count strictly exceeds store capacity bound.
    StoreCommitCapacityExceeded {
        /// Configured maximum commits.
        limit: usize,
        /// Actual attempted count.
        actual: usize,
    },
    /// Contradictions count for an event strictly exceeds hard bound.
    ContradictionCapacityExceeded {
        /// Event identifier.
        event_id: EventId,
        /// Configured limit.
        limit: usize,
        /// Actual count.
        actual: usize,
    },
    /// Evidence graphs count for a revision strictly exceeds hard bound.
    GraphCapacityExceeded {
        /// Event identifier.
        event_id: EventId,
        /// Revision number.
        revision: u64,
        /// Configured limit.
        limit: usize,
        /// Actual count.
        actual: usize,
    },
    /// Coverage witness count strictly exceeds store capacity bound.
    CoverageWitnessCapacityExceeded {
        /// Configured limit.
        limit: usize,
        /// Actual count.
        actual: usize,
    },
    /// A RotateCoverageRegistry commit does not match the live witness registry it claims to
    /// seal: canonical history and derived state disagree (fail-closed).
    CoverageRotationMismatch {
        /// Sealed witness count recorded by the rotation commit.
        sealed_count: u64,
        /// Live witness count observed at replay.
        live_count: usize,
    },
    /// Attempted revision number is not strictly monotonic.
    NonMonotonicRevision {
        /// Event identifier.
        event_id: EventId,
        /// Expected next revision number.
        expected: u64,
        /// Actual attempted revision number.
        actual: u64,
    },
    /// Genesis revision must have revision number 1.
    GenesisRevisionNotOne {
        /// Event identifier.
        event_id: EventId,
        /// Actual attempted revision number.
        actual: u64,
    },
    /// Genesis revision must begin in Hypothesized state.
    GenesisStateNotHypothesized {
        /// Event identifier.
        event_id: EventId,
        /// Actual attempted state.
        state: EventState,
    },
    /// Genesis revision cannot supersede a prior revision.
    GenesisHasSupersedes {
        /// Event identifier.
        event_id: EventId,
    },
    /// Superseding revision digest link does not match prior revision digest.
    SupersedesDigestMismatch {
        /// Event identifier.
        event_id: EventId,
        /// Expected digest of prior revision.
        expected: ContentDigest,
        /// Actual declared supersedes digest.
        actual: Option<ContentDigest>,
    },
    /// Event is in a terminal state (Resolved or Rejected) and cannot be superseded.
    TerminalStateImmutable {
        /// Event identifier.
        event_id: EventId,
        /// Terminal state reached.
        state: EventState,
    },
    /// State machine transition is not permitted.
    IllegalStateTransition {
        /// Event identifier.
        event_id: EventId,
        /// Transition failure detail.
        detail: EventTransitionError,
    },
    /// Event was not found in the store.
    EventNotFound(EventId),
    /// Target revision not found for event.
    RevisionNotFound {
        /// Event identifier.
        event_id: EventId,
        /// Target revision number.
        revision: u64,
    },
    /// Duplicate evidence graph identifier already committed.
    DuplicateGraphId(String),
    /// Commit sequence is not dense and monotonic.
    SequenceNotMonotonic {
        /// Expected sequence number.
        expected: u64,
        /// Actual sequence number.
        actual: u64,
    },
    /// Commit digest does not match commit contents or computed digest.
    CommitDigestMismatch {
        /// Sequence number of the commit.
        sequence: u64,
        /// Expected commit digest.
        expected: ContentDigest,
        /// Actual commit digest found in history.
        actual: ContentDigest,
    },
    /// Successor state root or anchor diverged during history replay.
    StateRootMismatch {
        /// Sequence number where divergence occurred.
        sequence: u64,
        /// Expected successor anchor from history.
        expected: Box<LedgerAnchor>,
        /// Actual rebuilt anchor.
        actual: Box<LedgerAnchor>,
    },
    /// Underlying event hypothesis failed validation.
    InvalidHypothesis(EventDecodeError),
    /// Underlying evidence graph failed validation.
    InvalidEvidenceGraph(EventDecodeError),
    /// Underlying contradiction failed validation.
    InvalidContradiction(BeliefError),
    /// Coverage domain string cannot be empty.
    EmptyCoverageDomain,
}

impl fmt::Display for EventStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleAnchor { expected, actual } => {
                write!(
                    f,
                    "event store commit rejected against stale anchor: expected seq {}, actual seq {}",
                    expected.commit_sequence, actual.commit_sequence
                )
            }
            Self::LineageDepthExceeded {
                event_id,
                limit,
                actual,
            } => {
                write!(
                    f,
                    "event {event_id} lineage depth {actual} exceeds limit {limit}"
                )
            }
            Self::StoreEventCapacityExceeded { limit, actual } => {
                write!(
                    f,
                    "event store capacity exceeded: {actual} events > limit {limit}"
                )
            }
            Self::StoreCommitCapacityExceeded { limit, actual } => {
                write!(
                    f,
                    "event store commit capacity exceeded: {actual} commits > limit {limit}"
                )
            }
            Self::ContradictionCapacityExceeded {
                event_id,
                limit,
                actual,
            } => {
                write!(
                    f,
                    "event {event_id} contradiction capacity exceeded: {actual} > limit {limit}"
                )
            }
            Self::GraphCapacityExceeded {
                event_id,
                revision,
                limit,
                actual,
            } => {
                write!(
                    f,
                    "event {event_id} rev {revision} graph capacity exceeded: {actual} > limit {limit}"
                )
            }
            Self::CoverageWitnessCapacityExceeded { limit, actual } => {
                write!(
                    f,
                    "coverage witness capacity exceeded: {actual} > limit {limit}"
                )
            }
            Self::CoverageRotationMismatch {
                sealed_count,
                live_count,
            } => {
                write!(
                    f,
                    "coverage registry rotation mismatch: commit seals {sealed_count} witnesses but the live registry holds {live_count}"
                )
            }
            Self::NonMonotonicRevision {
                event_id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "event {event_id} revision not monotonic: expected {expected}, actual {actual}"
                )
            }
            Self::GenesisRevisionNotOne { event_id, actual } => {
                write!(
                    f,
                    "event {event_id} genesis revision must be 1, actual {actual}"
                )
            }
            Self::GenesisStateNotHypothesized { event_id, state } => {
                write!(
                    f,
                    "event {event_id} genesis revision must begin in Hypothesized, actual {state:?}"
                )
            }
            Self::GenesisHasSupersedes { event_id } => {
                write!(
                    f,
                    "event {event_id} genesis revision cannot declare a superseded digest"
                )
            }
            Self::SupersedesDigestMismatch {
                event_id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "event {event_id} supersedes digest mismatch: expected {expected}, found {actual:?}"
                )
            }
            Self::TerminalStateImmutable { event_id, state } => {
                write!(
                    f,
                    "event {event_id} is in terminal state {state:?} and cannot be superseded"
                )
            }
            Self::IllegalStateTransition { event_id, detail } => {
                write!(f, "event {event_id} illegal transition: {detail}")
            }
            Self::EventNotFound(event_id) => {
                write!(f, "event not found: {event_id}")
            }
            Self::RevisionNotFound { event_id, revision } => {
                write!(f, "revision {revision} not found for event {event_id}")
            }
            Self::DuplicateGraphId(id) => {
                write!(f, "duplicate evidence graph id: {id}")
            }
            Self::SequenceNotMonotonic { expected, actual } => {
                write!(
                    f,
                    "commit sequence not monotonic: expected {expected}, actual {actual}"
                )
            }
            Self::CommitDigestMismatch {
                sequence,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "commit {sequence} digest mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::StateRootMismatch {
                sequence,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "rebuild state root mismatch at seq {sequence}: expected {}, actual {}",
                    expected.commit_sequence, actual.commit_sequence
                )
            }
            Self::InvalidHypothesis(err) => {
                write!(f, "invalid event hypothesis: {err:?}")
            }
            Self::InvalidEvidenceGraph(err) => {
                write!(f, "invalid evidence graph: {err:?}")
            }
            Self::InvalidContradiction(err) => {
                write!(f, "invalid contradiction: {err}")
            }
            Self::EmptyCoverageDomain => {
                write!(f, "coverage domain string cannot be empty")
            }
        }
    }
}

impl std::error::Error for EventStoreError {}

/// Reserved coverage-domain sentinel for an event whose domain was never declared.
const UNKNOWN_DOMAIN: &str = "unknown";

/// Returns `true` when `domain` cannot certify coverage: blank, or any spelling of the reserved
/// `unknown` sentinel regardless of ASCII case or surrounding whitespace.
fn is_unknown_domain(domain: &str) -> bool {
    let trimmed = domain.trim();
    trimmed.is_empty() || trimmed.eq_ignore_ascii_case(UNKNOWN_DOMAIN)
}

/// One typed mutation entry appended to the store's canonical log.
#[derive(Clone, Debug, PartialEq)]
pub enum EventStoreEntry {
    /// Genesis event revision (revision 1, Hypothesized).
    GenesisRevision {
        /// Genesis event hypothesis.
        revision: EventHypothesis,
        /// Coverage domain in which this event originated.
        coverage_domain: String,
    },
    /// Superseding event revision (revision > 1).
    SupersedeRevision {
        /// New superseding event hypothesis.
        revision: EventHypothesis,
    },
    /// Evidence graph attachment to an existing event revision.
    AttachEvidenceGraph {
        /// Validated evidence graph.
        graph: EvidenceGraph,
    },
    /// First-class contradiction recorded against an event.
    RecordContradiction {
        /// Event identifier.
        event_id: EventId,
        /// Physical contradiction details.
        contradiction: Contradiction,
    },
    /// Explicit coverage witness registration.
    RegisterCoverageWitness {
        /// Validated coverage witness.
        witness: CoverageWitness,
    },
    /// Seals and supersedes the live coverage-witness registry (fss-qlaao). Records the digest
    /// and count of the sealed witness set plus every witness refused while the registry was at
    /// capacity: refused domains stay blocked for absence certification.
    RotateCoverageRegistry {
        /// Digest over the sorted sealed witness set.
        sealed_digest: ContentDigest,
        /// Number of live witnesses sealed.
        sealed_count: u64,
        /// Witnesses refused while the registry was at capacity.
        refused: Vec<CoverageWitness>,
    },
}

impl CanonicalEncode for EventStoreEntry {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::GenesisRevision {
                revision,
                coverage_domain,
            } => {
                encoder.u8(1);
                revision.encode_canonical(encoder);
                encoder.text(coverage_domain);
            }
            Self::SupersedeRevision { revision } => {
                encoder.u8(2);
                revision.encode_canonical(encoder);
            }
            Self::AttachEvidenceGraph { graph } => {
                encoder.u8(3);
                graph.encode_canonical(encoder);
            }
            Self::RecordContradiction {
                event_id,
                contradiction,
            } => {
                encoder.u8(4);
                event_id.encode_canonical(encoder);
                contradiction.encode_canonical(encoder);
            }
            Self::RegisterCoverageWitness { witness } => {
                encoder.u8(5);
                witness.encode_canonical(encoder);
            }
            Self::RotateCoverageRegistry {
                sealed_digest,
                sealed_count,
                refused,
            } => {
                encoder.u8(6);
                sealed_digest.encode_canonical(encoder);
                encoder.u64(*sealed_count);
                encoder.u64(refused.len() as u64);
                for witness in refused {
                    witness.encode_canonical(encoder);
                }
            }
        }
    }
}

impl CanonicalDecode for EventStoreEntry {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let tag = decoder.u8()?;
        match tag {
            1 => {
                let revision = EventHypothesis::decode_canonical(decoder)?;
                let coverage_domain = decoder.text()?.to_string();
                Ok(Self::GenesisRevision {
                    revision,
                    coverage_domain,
                })
            }
            2 => {
                let revision = EventHypothesis::decode_canonical(decoder)?;
                Ok(Self::SupersedeRevision { revision })
            }
            3 => {
                let graph = EvidenceGraph::decode_canonical(decoder)?;
                Ok(Self::AttachEvidenceGraph { graph })
            }
            4 => {
                let event_id = EventId::decode_canonical(decoder)?;
                let contradiction = Contradiction::decode_canonical(decoder)?;
                Ok(Self::RecordContradiction {
                    event_id,
                    contradiction,
                })
            }
            5 => {
                let witness = CoverageWitness::decode_canonical(decoder)?;
                Ok(Self::RegisterCoverageWitness { witness })
            }
            6 => {
                let sealed_digest = ContentDigest::decode_canonical(decoder)?;
                let sealed_count = decoder.u64()?;
                let refused_len = decoder.u64()?;
                let mut refused = Vec::with_capacity(refused_len.min(1024) as usize);
                for _ in 0..refused_len {
                    refused.push(CoverageWitness::decode_canonical(decoder)?);
                }
                Ok(Self::RotateCoverageRegistry {
                    sealed_digest,
                    sealed_count,
                    refused,
                })
            }
            other => Err(ContractError::UnknownEntryTag(other)),
        }
    }
}

/// One immutable commit in the append-only canonical history of the store.
#[derive(Clone, Debug, PartialEq)]
pub struct EventStoreCommit {
    /// Monotonic 1-based commit sequence number.
    pub sequence: u64,
    /// Basis ledger anchor before applying this commit.
    pub basis_anchor: LedgerAnchor,
    /// Resulting ledger anchor after applying this commit.
    pub new_anchor: LedgerAnchor,
    /// Host receive or commit timestamp.
    pub commit_time: TimestampNs,
    /// Typed mutation payload.
    pub entry: EventStoreEntry,
    /// Canonical content digest over this commit.
    pub commit_digest: ContentDigest,
}

impl EventStoreCommit {
    /// Computes the canonical digest for a commit.
    #[must_use]
    pub fn compute_digest(
        sequence: u64,
        basis_anchor: &LedgerAnchor,
        new_anchor: &LedgerAnchor,
        commit_time: TimestampNs,
        entry: &EventStoreEntry,
    ) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(EVENT_STORE_COMMIT_DOMAIN);
        encoder.u64(sequence);
        basis_anchor.encode_canonical(&mut encoder);
        new_anchor.encode_canonical(&mut encoder);
        commit_time.encode_canonical(&mut encoder);
        entry.encode_canonical(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }
}

impl CanonicalEncode for EventStoreCommit {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(EVENT_STORE_COMMIT_DOMAIN);
        encoder.u64(self.sequence);
        self.basis_anchor.encode_canonical(encoder);
        self.new_anchor.encode_canonical(encoder);
        self.commit_time.encode_canonical(encoder);
        self.entry.encode_canonical(encoder);
        encoder.digest(self.commit_digest);
    }
}

impl CanonicalDecode for EventStoreCommit {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let domain = decoder.text()?;
        if domain != EVENT_STORE_COMMIT_DOMAIN {
            return Err(ContractError::InvalidIdentifier);
        }
        let sequence = decoder.u64()?;
        let basis_anchor = LedgerAnchor::decode_canonical(decoder)?;
        let new_anchor = LedgerAnchor::decode_canonical(decoder)?;
        let commit_time = TimestampNs::decode_canonical(decoder)?;
        let entry = EventStoreEntry::decode_canonical(decoder)?;
        let commit_digest = decoder.digest()?;
        Ok(Self {
            sequence,
            basis_anchor,
            new_anchor,
            commit_time,
            entry,
            commit_digest,
        })
    }
}

/// Specific reason why a read of an event, lineage, or graph is not observable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotObservableReason {
    /// No coverage witness is registered for the requested domain.
    NoCoverageWitness,
    /// The registered coverage witness has gaps in its continuity window.
    CoverageWitnessGapped,
    /// The coverage witness is incomplete or did not certify complete evaluation.
    CoverageWitnessUncertified,
    /// The queried domain is outside the authorized/observed domain.
    DomainNotCovered {
        /// Domain string queried.
        queried: String,
    },
    /// The authorized generation differs from observed generation.
    GenerationMismatch {
        /// Expected authorized generation.
        expected: u64,
        /// Actual observed generation.
        observed: u64,
    },
    /// Domain was explicitly excluded in the coverage witness.
    ExcludedDomain {
        /// Excluded domain string.
        domain: String,
    },
    /// The event domain is unknown; absence cannot be certified without a declared domain.
    UnknownDomain,
    /// Target revision was not found in the recorded event lineage.
    RevisionNotFound {
        /// Requested revision number.
        revision: u64,
    },
    /// The store is at coverage-witness or commit capacity, so a later coverage witness (possibly
    /// one reporting a gap) can no longer be admitted; absence cannot be certified for any domain.
    CoverageRegistryCapacityExceeded,
}

impl fmt::Display for NotObservableReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCoverageWitness => {
                write!(f, "no CoverageWitness registered for domain")
            }
            Self::CoverageWitnessGapped => {
                write!(f, "CoverageWitness contains continuity gaps")
            }
            Self::CoverageWitnessUncertified => {
                write!(f, "CoverageWitness does not certify complete absence")
            }
            Self::DomainNotCovered { queried } => {
                write!(f, "queried domain '{queried}' is not covered")
            }
            Self::GenerationMismatch { expected, observed } => {
                write!(
                    f,
                    "generation mismatch: authorized {expected}, observed {observed}"
                )
            }
            Self::ExcludedDomain { domain } => {
                write!(f, "domain '{domain}' is explicitly excluded in coverage")
            }
            Self::UnknownDomain => {
                write!(
                    f,
                    "event domain is unknown; absence cannot be certified without a domain"
                )
            }
            Self::RevisionNotFound { revision } => {
                write!(f, "revision {revision} not found in recorded lineage")
            }
            Self::CoverageRegistryCapacityExceeded => {
                write!(
                    f,
                    "coverage registry at capacity; a later coverage gap could not be admitted, so absence cannot be certified"
                )
            }
        }
    }
}

/// Result of querying an event revision from the store.
#[derive(Clone, Debug, PartialEq)]
pub enum EventReadResult<'a> {
    /// The revision is present and observed.
    Found(&'a EventHypothesis),
    /// Domain is verified by a valid CoverageWitness certifying that the revision does not exist.
    AbsentWithCoverage(&'a CoverageWitness),
    /// Query is outside certified coverage; absence cannot be asserted.
    NotObservable {
        /// Queried coverage domain.
        domain: String,
        /// Specific non-observability reason (primary under canonical precedence).
        reason: NotObservableReason,
        /// Full set of non-observability reasons that applied, in canonical precedence order.
        all_reasons: Vec<NotObservableReason>,
    },
}

/// Result of querying an event lineage from the store.
#[derive(Clone, Debug, PartialEq)]
pub enum LineageReadResult<'a> {
    /// The event lineage is present and observed.
    Found(&'a EventLineage),
    /// Domain is verified by a valid CoverageWitness certifying that the event does not exist.
    AbsentWithCoverage(&'a CoverageWitness),
    /// Query is outside certified coverage; absence cannot be asserted.
    NotObservable {
        /// Queried coverage domain.
        domain: String,
        /// Specific non-observability reason (primary under canonical precedence).
        reason: NotObservableReason,
        /// Full set of non-observability reasons that applied, in canonical precedence order.
        all_reasons: Vec<NotObservableReason>,
    },
}

/// Result of querying an evidence graph from the store.
#[derive(Clone, Debug, PartialEq)]
pub enum GraphReadResult<'a> {
    /// The evidence graph is present and observed.
    Found(&'a EvidenceGraph),
    /// Domain is verified by a valid CoverageWitness certifying that the graph does not exist.
    AbsentWithCoverage(&'a CoverageWitness),
    /// Query is outside certified coverage; absence cannot be asserted.
    NotObservable {
        /// Queried coverage domain.
        domain: String,
        /// Specific non-observability reason (primary under canonical precedence).
        reason: NotObservableReason,
        /// Full set of non-observability reasons that applied, in canonical precedence order.
        all_reasons: Vec<NotObservableReason>,
    },
}

/// Deterministic, append-only event evidence graph and revision store (FSS-081).
#[derive(Clone, Debug, PartialEq)]
pub struct EventRevisionStore {
    current_anchor: LedgerAnchor,
    history: Vec<EventStoreCommit>,
    // Derived state:
    lineages: BTreeMap<EventId, EventLineage>,
    event_domains: BTreeMap<EventId, String>,
    graphs_by_id: BTreeMap<String, EvidenceGraph>,
    graphs_by_revision: BTreeMap<(EventId, u64), Vec<String>>,
    contradictions: BTreeMap<EventId, Vec<Contradiction>>,
    unresolved_worlds: BTreeSet<String>,
    coverage_witnesses: Vec<CoverageWitness>,
    // Derived from RotateCoverageRegistry commits: refused witnesses recorded by rotations.
    // Their domains stay blocked for absence certification (fss-qlaao).
    rotated_refused: Vec<CoverageWitness>,
}

impl EventRevisionStore {
    /// Creates a new empty store starting at the specified genesis anchor.
    #[must_use]
    pub fn new(genesis_anchor: LedgerAnchor) -> Self {
        Self {
            current_anchor: genesis_anchor,
            history: Vec::new(),
            lineages: BTreeMap::new(),
            event_domains: BTreeMap::new(),
            graphs_by_id: BTreeMap::new(),
            graphs_by_revision: BTreeMap::new(),
            contradictions: BTreeMap::new(),
            unresolved_worlds: BTreeSet::new(),
            coverage_witnesses: Vec::new(),
            rotated_refused: Vec::new(),
        }
    }

    /// Returns the current state anchor of the store.
    #[must_use]
    pub const fn current_anchor(&self) -> &LedgerAnchor {
        &self.current_anchor
    }

    /// Returns `true` when the store can no longer admit a coverage witness: the witness registry
    /// holds [`MAX_STORE_COVERAGE_WITNESSES`] witnesses or the history holds [`MAX_STORE_COMMITS`]
    /// commits.
    ///
    /// Both counts are pure functions of canonical history, so a store rebuilt with
    /// [`Self::rebuild_from_history`] reports exactly the same value as the live store. While this
    /// is `true`, every coverage-for-absence evaluation fails closed with
    /// [`NotObservableReason::CoverageRegistryCapacityExceeded`].
    #[must_use]
    pub fn coverage_registry_at_capacity(&self) -> bool {
        self.coverage_witnesses.len() >= MAX_STORE_COVERAGE_WITNESSES
            || self.history.len() >= MAX_STORE_COMMITS
    }

    /// Returns the immutable append-only commit history of the store.
    #[must_use]
    pub fn history(&self) -> &[EventStoreCommit] {
        &self.history
    }

    /// Returns the number of commits recorded in the history.
    #[must_use]
    pub fn commit_count(&self) -> usize {
        self.history.len()
    }

    /// Returns the number of distinct event lineages tracked in derived state.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.lineages.len()
    }

    /// Returns the set of unresolved worlds kept alive by active contradictions.
    ///
    /// Agrees with [`Self::has_contradiction`]: a contradiction recorded with a terminal
    /// disposition contributes no world here.
    #[must_use]
    pub const fn unresolved_worlds(&self) -> &BTreeSet<String> {
        &self.unresolved_worlds
    }

    /// Checks whether a specific world identifier remains unresolved.
    #[must_use]
    pub fn is_world_unresolved(&self, world_id: &str) -> bool {
        self.unresolved_worlds.contains(world_id)
    }

    /// Returns all first-class contradictions recorded against a specific event.
    #[must_use]
    pub fn contradictions_for_event(&self, event_id: &EventId) -> &[Contradiction] {
        self.contradictions.get(event_id).map_or(&[], Vec::as_slice)
    }

    /// Returns true if any contradictions are active for the specified event.
    ///
    /// Contradictions are append-only and keep the disposition they were recorded with; nothing
    /// here changes that disposition later. One recorded with a terminal disposition (refuted,
    /// resolved, superseded) is listed by [`Self::contradictions_for_event`] but never counts
    /// here, and one recorded active counts for as long as it is retained. See
    /// [`Contradiction::is_active`].
    #[must_use]
    pub fn has_contradiction(&self, event_id: &EventId) -> bool {
        self.contradictions
            .get(event_id)
            .is_some_and(|c| c.iter().any(Contradiction::is_active))
    }

    /// Appends a genesis event revision (revision 1) to the store.
    pub fn append_genesis(
        &mut self,
        basis_anchor: LedgerAnchor,
        genesis: EventHypothesis,
        coverage_domain: impl Into<String>,
        commit_time: TimestampNs,
    ) -> Result<ContentDigest, EventStoreError> {
        let coverage_domain = coverage_domain.into();
        if coverage_domain.trim().is_empty() {
            return Err(EventStoreError::EmptyCoverageDomain);
        }
        self.check_basis_anchor(&basis_anchor)?;
        if self.history.len() >= MAX_STORE_COMMITS {
            return Err(EventStoreError::StoreCommitCapacityExceeded {
                limit: MAX_STORE_COMMITS,
                actual: self.history.len() + 1,
            });
        }
        if self.lineages.len() >= MAX_STORE_EVENTS && !self.lineages.contains_key(&genesis.event_id)
        {
            return Err(EventStoreError::StoreEventCapacityExceeded {
                limit: MAX_STORE_EVENTS,
                actual: self.lineages.len() + 1,
            });
        }
        if genesis.revision != 1 {
            return Err(EventStoreError::GenesisRevisionNotOne {
                event_id: genesis.event_id.clone(),
                actual: genesis.revision,
            });
        }
        if genesis.state != EventState::Hypothesized {
            return Err(EventStoreError::GenesisStateNotHypothesized {
                event_id: genesis.event_id.clone(),
                state: genesis.state,
            });
        }
        if genesis.supersedes.is_some() {
            return Err(EventStoreError::GenesisHasSupersedes {
                event_id: genesis.event_id.clone(),
            });
        }
        if self.lineages.contains_key(&genesis.event_id) {
            return Err(EventStoreError::NonMonotonicRevision {
                event_id: genesis.event_id.clone(),
                expected: 2,
                actual: 1,
            });
        }
        genesis
            .verify()
            .map_err(EventStoreError::InvalidHypothesis)?;

        let lineage = EventLineage::new(genesis.clone()).map_err(|err| {
            EventStoreError::IllegalStateTransition {
                event_id: genesis.event_id.clone(),
                detail: err,
            }
        })?;

        let entry = EventStoreEntry::GenesisRevision {
            revision: genesis.clone(),
            coverage_domain: coverage_domain.clone(),
        };

        let digest = self.commit_entry(entry, commit_time)?;
        self.lineages.insert(genesis.event_id.clone(), lineage);
        self.event_domains.insert(genesis.event_id, coverage_domain);
        Ok(digest)
    }

    /// Appends a superseding event revision via state machine transition.
    pub fn append_transition(
        &mut self,
        basis_anchor: LedgerAnchor,
        event_id: &EventId,
        params: EventTransitionParams,
        commit_time: TimestampNs,
    ) -> Result<ContentDigest, EventStoreError> {
        self.check_basis_anchor(&basis_anchor)?;
        if self.history.len() >= MAX_STORE_COMMITS {
            return Err(EventStoreError::StoreCommitCapacityExceeded {
                limit: MAX_STORE_COMMITS,
                actual: self.history.len() + 1,
            });
        }

        let lineage = self
            .lineages
            .get(event_id)
            .ok_or_else(|| EventStoreError::EventNotFound(event_id.clone()))?;

        if lineage.len() >= MAX_STORE_LINEAGE_DEPTH {
            return Err(EventStoreError::LineageDepthExceeded {
                event_id: event_id.clone(),
                limit: MAX_STORE_LINEAGE_DEPTH,
                actual: lineage.len() + 1,
            });
        }

        let mut updated_lineage = lineage.clone();
        let new_revision = updated_lineage
            .transition(params)
            .map_err(|err| match err {
                EventTransitionError::TerminalStateImmutable { state } => {
                    EventStoreError::TerminalStateImmutable {
                        event_id: event_id.clone(),
                        state,
                    }
                }
                other => EventStoreError::IllegalStateTransition {
                    event_id: event_id.clone(),
                    detail: other,
                },
            })?
            .clone();

        let entry = EventStoreEntry::SupersedeRevision {
            revision: new_revision,
        };

        let digest = self.commit_entry(entry, commit_time)?;
        self.lineages.insert(event_id.clone(), updated_lineage);
        Ok(digest)
    }

    /// Appends an explicitly constructed superseding revision.
    pub fn append_revision(
        &mut self,
        basis_anchor: LedgerAnchor,
        revision: EventHypothesis,
        commit_time: TimestampNs,
    ) -> Result<ContentDigest, EventStoreError> {
        self.check_basis_anchor(&basis_anchor)?;
        if self.history.len() >= MAX_STORE_COMMITS {
            return Err(EventStoreError::StoreCommitCapacityExceeded {
                limit: MAX_STORE_COMMITS,
                actual: self.history.len() + 1,
            });
        }

        let lineage = self
            .lineages
            .get(&revision.event_id)
            .ok_or_else(|| EventStoreError::EventNotFound(revision.event_id.clone()))?;

        if lineage.len() >= MAX_STORE_LINEAGE_DEPTH {
            return Err(EventStoreError::LineageDepthExceeded {
                event_id: revision.event_id.clone(),
                limit: MAX_STORE_LINEAGE_DEPTH,
                actual: lineage.len() + 1,
            });
        }

        let current = lineage.current();
        if current.state.is_terminal() {
            return Err(EventStoreError::TerminalStateImmutable {
                event_id: revision.event_id.clone(),
                state: current.state,
            });
        }

        let expected_rev = current.revision + 1;
        if revision.revision != expected_rev {
            return Err(EventStoreError::NonMonotonicRevision {
                event_id: revision.event_id.clone(),
                expected: expected_rev,
                actual: revision.revision,
            });
        }

        let expected_prior_digest = current.canonical_digest(EventHypothesis::SCHEMA);
        if revision.supersedes != Some(expected_prior_digest) {
            return Err(EventStoreError::SupersedesDigestMismatch {
                event_id: revision.event_id.clone(),
                expected: expected_prior_digest,
                actual: revision.supersedes,
            });
        }

        revision
            .verify()
            .map_err(EventStoreError::InvalidHypothesis)?;

        // Verify transition rule validity
        let transition_params = EventTransitionParams {
            target_state: revision.state,
            kind: revision.kind,
            interval: revision.interval,
            uncertainty_reason: revision.uncertainty_reason.clone(),
            zone_ids: revision.zone_ids.clone(),
            track_ids: revision.track_ids.clone(),
            probability: revision.probability,
            evidence: revision.evidence.clone(),
            model_receipts: revision.model_receipts.clone(),
            decision_path: revision.decision_path.clone(),
            urgent_single_sensor: revision
                .uncertainty_reason
                .as_deref()
                .is_some_and(|r| r.contains(crate::event::SINGLE_DOMAIN_UNCONFIRMED_LABEL)),
        };

        let mut updated_lineage = lineage.clone();
        updated_lineage
            .transition(transition_params)
            .map_err(|err| match err {
                EventTransitionError::OverLimitLength { .. } => {
                    EventStoreError::LineageDepthExceeded {
                        event_id: revision.event_id.clone(),
                        limit: MAX_STORE_LINEAGE_DEPTH,
                        actual: lineage.len() + 1,
                    }
                }
                EventTransitionError::TerminalStateImmutable { state } => {
                    EventStoreError::TerminalStateImmutable {
                        event_id: revision.event_id.clone(),
                        state,
                    }
                }
                other => EventStoreError::IllegalStateTransition {
                    event_id: revision.event_id.clone(),
                    detail: other,
                },
            })?;

        let entry = EventStoreEntry::SupersedeRevision {
            revision: revision.clone(),
        };

        let digest = self.commit_entry(entry, commit_time)?;
        self.lineages.insert(revision.event_id, updated_lineage);
        Ok(digest)
    }

    /// Attaches an evidence graph to an existing event revision.
    pub fn attach_evidence_graph(
        &mut self,
        basis_anchor: LedgerAnchor,
        graph: EvidenceGraph,
        commit_time: TimestampNs,
    ) -> Result<ContentDigest, EventStoreError> {
        self.check_basis_anchor(&basis_anchor)?;
        if self.history.len() >= MAX_STORE_COMMITS {
            return Err(EventStoreError::StoreCommitCapacityExceeded {
                limit: MAX_STORE_COMMITS,
                actual: self.history.len() + 1,
            });
        }
        if self.graphs_by_id.contains_key(&graph.graph_id) {
            return Err(EventStoreError::DuplicateGraphId(graph.graph_id.clone()));
        }

        graph
            .verify()
            .map_err(EventStoreError::InvalidEvidenceGraph)?;

        let lineage = self
            .lineages
            .get(&graph.event_id)
            .ok_or_else(|| EventStoreError::EventNotFound(graph.event_id.clone()))?;

        if graph.revision == 0 || graph.revision > lineage.current_revision() {
            return Err(EventStoreError::RevisionNotFound {
                event_id: graph.event_id.clone(),
                revision: graph.revision,
            });
        }

        let rev_key = (graph.event_id.clone(), graph.revision);
        let current_count = self.graphs_by_revision.get(&rev_key).map_or(0, Vec::len);
        if current_count >= MAX_GRAPHS_PER_REVISION {
            return Err(EventStoreError::GraphCapacityExceeded {
                event_id: graph.event_id.clone(),
                revision: graph.revision,
                limit: MAX_GRAPHS_PER_REVISION,
                actual: current_count + 1,
            });
        }

        let graph_id = graph.graph_id.clone();
        let entry = EventStoreEntry::AttachEvidenceGraph {
            graph: graph.clone(),
        };

        let digest = self.commit_entry(entry, commit_time)?;
        self.graphs_by_id.insert(graph_id.clone(), graph);
        self.graphs_by_revision
            .entry(rev_key)
            .or_default()
            .push(graph_id);
        Ok(digest)
    }

    /// Records a first-class physical contradiction against an event.
    ///
    /// Every valid contradiction is retained, but only an active one keeps its unresolved worlds
    /// alive, so [`Self::is_world_unresolved`] agrees with [`Self::has_contradiction`].
    pub fn record_contradiction(
        &mut self,
        basis_anchor: LedgerAnchor,
        event_id: EventId,
        contradiction: Contradiction,
        commit_time: TimestampNs,
    ) -> Result<ContentDigest, EventStoreError> {
        self.check_basis_anchor(&basis_anchor)?;
        if self.history.len() >= MAX_STORE_COMMITS {
            return Err(EventStoreError::StoreCommitCapacityExceeded {
                limit: MAX_STORE_COMMITS,
                actual: self.history.len() + 1,
            });
        }
        if !self.lineages.contains_key(&event_id) {
            return Err(EventStoreError::EventNotFound(event_id));
        }

        contradiction
            .verify()
            .map_err(EventStoreError::InvalidContradiction)?;

        let current_count = self.contradictions.get(&event_id).map_or(0, Vec::len);
        if current_count >= MAX_CONTRADICTIONS_PER_EVENT {
            return Err(EventStoreError::ContradictionCapacityExceeded {
                event_id,
                limit: MAX_CONTRADICTIONS_PER_EVENT,
                actual: current_count + 1,
            });
        }

        if contradiction.is_active() {
            for world in contradiction.unresolved_worlds() {
                self.unresolved_worlds.insert(world.clone());
            }
        }

        let entry = EventStoreEntry::RecordContradiction {
            event_id: event_id.clone(),
            contradiction: contradiction.clone(),
        };

        let digest = self.commit_entry(entry, commit_time)?;
        self.contradictions
            .entry(event_id)
            .or_default()
            .push(contradiction);
        Ok(digest)
    }

    /// Registers a coverage witness in the store.
    pub fn register_coverage_witness(
        &mut self,
        basis_anchor: LedgerAnchor,
        witness: CoverageWitness,
        commit_time: TimestampNs,
    ) -> Result<ContentDigest, EventStoreError> {
        // The stale-basis check comes first: a caller on a stale basis learns that before any
        // capacity outcome. A capacity refusal leaves no trace outside canonical history; the
        // store is already at capacity, and every absence evaluation fails closed while it is.
        self.check_basis_anchor(&basis_anchor)?;
        if self.history.len() >= MAX_STORE_COMMITS {
            return Err(EventStoreError::StoreCommitCapacityExceeded {
                limit: MAX_STORE_COMMITS,
                actual: self.history.len() + 1,
            });
        }
        if self.coverage_witnesses.len() >= MAX_STORE_COVERAGE_WITNESSES {
            return Err(EventStoreError::CoverageWitnessCapacityExceeded {
                limit: MAX_STORE_COVERAGE_WITNESSES,
                actual: self.coverage_witnesses.len() + 1,
            });
        }

        let entry = EventStoreEntry::RegisterCoverageWitness {
            witness: witness.clone(),
        };

        let digest = self.commit_entry(entry, commit_time)?;
        self.coverage_witnesses.push(witness);
        Ok(digest)
    }

    /// Seals and supersedes the live coverage-witness registry (fss-qlaao).
    ///
    /// The rotation is a canonical commit: it records the seal digest and count of the live
    /// witness set plus every witness the caller reports as refused while the registry was at
    /// capacity, so a store rebuilt with [`Self::rebuild_from_history`] reaches the identical
    /// state. Afterwards the live registry is empty, new witnesses are admitted again, and
    /// absence is certifiable only from witnesses registered after the rotation. Domains named
    /// by a refused witness stay blocked: a refused report never entered canonical custody, so
    /// absence can never be certified across it. The commit-history capacity bound still
    /// applies and is unaffected by rotation.
    pub fn rotate_coverage_registry(
        &mut self,
        basis_anchor: LedgerAnchor,
        refused: Vec<CoverageWitness>,
        commit_time: TimestampNs,
    ) -> Result<ContentDigest, EventStoreError> {
        self.check_basis_anchor(&basis_anchor)?;
        if self.history.len() >= MAX_STORE_COMMITS {
            return Err(EventStoreError::StoreCommitCapacityExceeded {
                limit: MAX_STORE_COMMITS,
                actual: self.history.len() + 1,
            });
        }
        let sealed_digest = Self::sealed_witness_digest(&self.coverage_witnesses);
        let sealed_count = self.coverage_witnesses.len() as u64;
        let entry = EventStoreEntry::RotateCoverageRegistry {
            sealed_digest,
            sealed_count,
            refused: refused.clone(),
        };
        let digest = self.commit_entry(entry, commit_time)?;
        self.rotated_refused.extend(refused);
        self.coverage_witnesses.clear();
        Ok(digest)
    }

    /// Computes the seal digest over a witness set: per-witness canonical digests, sorted, then
    /// digested with the count prefix. Independent of registration order.
    fn sealed_witness_digest(witnesses: &[CoverageWitness]) -> ContentDigest {
        let mut digests: Vec<ContentDigest> = witnesses
            .iter()
            .map(|w| {
                let mut encoder = CanonicalEncoder::new();
                w.encode_canonical(&mut encoder);
                ContentDigest::sha256(&encoder.finish())
            })
            .collect();
        digests.sort();
        let mut encoder = CanonicalEncoder::new();
        encoder.u64(digests.len() as u64);
        for digest in &digests {
            digest.encode_canonical(&mut encoder);
        }
        ContentDigest::sha256(&encoder.finish())
    }

    /// Applies a `RotateCoverageRegistry` commit during replay, verifying the recorded seal
    /// against the live registry (fail-closed on any disagreement).
    fn apply_coverage_rotation(
        &mut self,
        sealed_digest: ContentDigest,
        sealed_count: u64,
        refused: Vec<CoverageWitness>,
    ) -> Result<ContentDigest, EventStoreError> {
        let live_count = self.coverage_witnesses.len();
        if sealed_count != live_count as u64
            || sealed_digest != Self::sealed_witness_digest(&self.coverage_witnesses)
        {
            return Err(EventStoreError::CoverageRotationMismatch {
                sealed_count,
                live_count,
            });
        }
        self.rotated_refused.extend(refused);
        self.coverage_witnesses.clear();
        Ok(sealed_digest)
    }

    /// Returns the witnesses recorded as refused by coverage-registry rotations. Their domains
    /// can never certify absence.
    #[must_use]
    pub fn rotated_refused(&self) -> &[CoverageWitness] {
        &self.rotated_refused
    }

    /// Reads an event revision from the store.
    ///
    /// If `at_revision` is `None`, returns the latest revision.
    /// If the revision is not present, evaluates coverage witnesses for the event's domain.
    /// Outside coverage, returns typed `NotObservable`, never absence.
    pub fn read_event(
        &self,
        event_id: &EventId,
        at_revision: Option<u64>,
    ) -> Result<EventReadResult<'_>, EventStoreError> {
        if let Some(lineage) = self.lineages.get(event_id) {
            match at_revision {
                None => Ok(EventReadResult::Found(lineage.current())),
                Some(target_rev) => {
                    if let Some(rev) = lineage.history().iter().find(|r| r.revision == target_rev) {
                        Ok(EventReadResult::Found(rev))
                    } else {
                        let domain = self
                            .event_domains
                            .get(event_id)
                            .cloned()
                            .unwrap_or_else(|| UNKNOWN_DOMAIN.to_string());
                        let reason = NotObservableReason::RevisionNotFound {
                            revision: target_rev,
                        };
                        Ok(EventReadResult::NotObservable {
                            domain,
                            all_reasons: vec![reason.clone()],
                            reason,
                        })
                    }
                }
            }
        } else if let Some(domain) = self.event_domains.get(event_id) {
            if is_unknown_domain(domain) {
                Ok(EventReadResult::NotObservable {
                    domain: domain.clone(),
                    reason: NotObservableReason::UnknownDomain,
                    all_reasons: vec![NotObservableReason::UnknownDomain],
                })
            } else {
                Ok(self.evaluate_coverage(domain).into_event_read(domain))
            }
        } else {
            Ok(EventReadResult::NotObservable {
                domain: UNKNOWN_DOMAIN.to_string(),
                reason: NotObservableReason::UnknownDomain,
                all_reasons: vec![NotObservableReason::UnknownDomain],
            })
        }
    }

    /// Reads an event revision within an explicitly declared coverage domain.
    pub fn read_event_in_domain(
        &self,
        event_id: &EventId,
        domain: &str,
        at_revision: Option<u64>,
    ) -> Result<EventReadResult<'_>, EventStoreError> {
        if let Some(lineage) = self.lineages.get(event_id) {
            match at_revision {
                None => Ok(EventReadResult::Found(lineage.current())),
                Some(target_rev) => {
                    if let Some(rev) = lineage.history().iter().find(|r| r.revision == target_rev) {
                        Ok(EventReadResult::Found(rev))
                    } else {
                        let reason = NotObservableReason::RevisionNotFound {
                            revision: target_rev,
                        };
                        Ok(EventReadResult::NotObservable {
                            domain: domain.to_string(),
                            all_reasons: vec![reason.clone()],
                            reason,
                        })
                    }
                }
            }
        } else {
            Ok(self.evaluate_coverage(domain).into_event_read(domain))
        }
    }

    /// Reads an event lineage from the store.
    pub fn read_lineage(
        &self,
        event_id: &EventId,
    ) -> Result<LineageReadResult<'_>, EventStoreError> {
        if let Some(lineage) = self.lineages.get(event_id) {
            Ok(LineageReadResult::Found(lineage))
        } else if let Some(domain) = self.event_domains.get(event_id) {
            if is_unknown_domain(domain) {
                Ok(LineageReadResult::NotObservable {
                    domain: domain.clone(),
                    reason: NotObservableReason::UnknownDomain,
                    all_reasons: vec![NotObservableReason::UnknownDomain],
                })
            } else {
                Ok(self.evaluate_coverage(domain).into_lineage_read(domain))
            }
        } else {
            Ok(LineageReadResult::NotObservable {
                domain: UNKNOWN_DOMAIN.to_string(),
                reason: NotObservableReason::UnknownDomain,
                all_reasons: vec![NotObservableReason::UnknownDomain],
            })
        }
    }

    /// Reads an event lineage within an explicitly declared coverage domain.
    pub fn read_lineage_in_domain(
        &self,
        event_id: &EventId,
        domain: &str,
    ) -> Result<LineageReadResult<'_>, EventStoreError> {
        if let Some(lineage) = self.lineages.get(event_id) {
            Ok(LineageReadResult::Found(lineage))
        } else {
            Ok(self.evaluate_coverage(domain).into_lineage_read(domain))
        }
    }

    /// Reads all evidence graphs attached to a specific event revision.
    pub fn read_evidence_graphs(
        &self,
        event_id: &EventId,
        revision: u64,
    ) -> Result<Vec<&EvidenceGraph>, EventStoreError> {
        let rev_key = (event_id.clone(), revision);
        if let Some(ids) = self.graphs_by_revision.get(&rev_key) {
            let mut graphs = Vec::with_capacity(ids.len());
            for id in ids {
                if let Some(g) = self.graphs_by_id.get(id) {
                    graphs.push(g);
                }
            }
            Ok(graphs)
        } else if let Some(lineage) = self.lineages.get(event_id) {
            if lineage.history().iter().any(|r| r.revision == revision) {
                Ok(Vec::new())
            } else {
                Err(EventStoreError::RevisionNotFound {
                    event_id: event_id.clone(),
                    revision,
                })
            }
        } else {
            Err(EventStoreError::EventNotFound(event_id.clone()))
        }
    }

    /// Reads one evidence graph by its unique graph identifier.
    pub fn read_evidence_graph(
        &self,
        graph_id: &str,
        domain: &str,
    ) -> Result<GraphReadResult<'_>, EventStoreError> {
        if let Some(graph) = self.graphs_by_id.get(graph_id) {
            Ok(GraphReadResult::Found(graph))
        } else {
            Ok(self.evaluate_coverage(domain).into_graph_read(domain))
        }
    }

    /// Rebuilds derived store state from scratch by replaying canonical commit history.
    ///
    /// Proves INV-015: derived state is completely rebuildable from canonical history.
    pub fn rebuild_from_history(
        genesis_anchor: LedgerAnchor,
        history: &[EventStoreCommit],
    ) -> Result<Self, EventStoreError> {
        let mut store = Self::new(genesis_anchor);
        for commit in history {
            if commit.sequence != (store.history.len() as u64) + 1 {
                return Err(EventStoreError::SequenceNotMonotonic {
                    expected: (store.history.len() as u64) + 1,
                    actual: commit.sequence,
                });
            }
            if commit.basis_anchor != store.current_anchor {
                return Err(EventStoreError::StaleAnchor {
                    expected: Box::new(store.current_anchor.clone()),
                    actual: Box::new(commit.basis_anchor.clone()),
                });
            }

            // Each replay call returns the digest of the commit it just appended, so the
            // rebuilt digest is always available without re-reading the history tail.
            let rebuilt_digest = match &commit.entry {
                EventStoreEntry::GenesisRevision {
                    revision,
                    coverage_domain,
                } => store.append_genesis(
                    commit.basis_anchor.clone(),
                    revision.clone(),
                    coverage_domain.clone(),
                    commit.commit_time,
                )?,
                EventStoreEntry::SupersedeRevision { revision } => store.append_revision(
                    commit.basis_anchor.clone(),
                    revision.clone(),
                    commit.commit_time,
                )?,
                EventStoreEntry::AttachEvidenceGraph { graph } => store.attach_evidence_graph(
                    commit.basis_anchor.clone(),
                    graph.clone(),
                    commit.commit_time,
                )?,
                EventStoreEntry::RecordContradiction {
                    event_id,
                    contradiction,
                } => store.record_contradiction(
                    commit.basis_anchor.clone(),
                    event_id.clone(),
                    contradiction.clone(),
                    commit.commit_time,
                )?,
                EventStoreEntry::RegisterCoverageWitness { witness } => store
                    .register_coverage_witness(
                        commit.basis_anchor.clone(),
                        witness.clone(),
                        commit.commit_time,
                    )?,
                EventStoreEntry::RotateCoverageRegistry {
                    sealed_digest,
                    sealed_count,
                    refused,
                } => store.apply_coverage_rotation(
                    *sealed_digest,
                    *sealed_count,
                    refused.clone(),
                )?,
            };

            // Verify the rebuilt state anchor matches the recorded new_anchor
            if store.current_anchor != commit.new_anchor {
                return Err(EventStoreError::StateRootMismatch {
                    sequence: commit.sequence,
                    expected: Box::new(commit.new_anchor.clone()),
                    actual: Box::new(store.current_anchor.clone()),
                });
            }

            // Verify the commit digest matches the rebuilt commit
            if commit.commit_digest != rebuilt_digest {
                return Err(EventStoreError::CommitDigestMismatch {
                    sequence: commit.sequence,
                    expected: rebuilt_digest,
                    actual: commit.commit_digest,
                });
            }
        }
        Ok(store)
    }

    fn check_basis_anchor(&self, basis_anchor: &LedgerAnchor) -> Result<(), EventStoreError> {
        if *basis_anchor != self.current_anchor {
            return Err(EventStoreError::StaleAnchor {
                expected: Box::new(self.current_anchor.clone()),
                actual: Box::new(basis_anchor.clone()),
            });
        }
        Ok(())
    }

    fn commit_entry(
        &mut self,
        entry: EventStoreEntry,
        commit_time: TimestampNs,
    ) -> Result<ContentDigest, EventStoreError> {
        let sequence = (self.history.len() as u64) + 1;
        let mut entry_encoder = CanonicalEncoder::new();
        entry.encode_canonical(&mut entry_encoder);
        let entry_digest = ContentDigest::sha256(&entry_encoder.finish());

        let mut new_anchor = self.current_anchor.clone();
        new_anchor.commit_sequence = sequence;
        new_anchor.state_root =
            compute_state_root(self.current_anchor.state_root, sequence, entry_digest);

        let commit_digest = EventStoreCommit::compute_digest(
            sequence,
            &self.current_anchor,
            &new_anchor,
            commit_time,
            &entry,
        );

        let commit = EventStoreCommit {
            sequence,
            basis_anchor: self.current_anchor.clone(),
            new_anchor: new_anchor.clone(),
            commit_time,
            entry,
            commit_digest,
        };

        self.history.push(commit);
        self.current_anchor = new_anchor;
        Ok(commit_digest)
    }

    /// Returns the full set of non-observability reasons for `domain` in canonical precedence order:
    /// 1. `CoverageRegistryCapacityExceeded`: the store is at coverage-witness or commit capacity.
    /// 2. `CoverageWitnessGapped`: physical continuity gap in observation window.
    /// 3. `ExcludedDomain`: domain was explicitly excluded in witness.
    /// 4. `GenerationMismatch`: authorized generation differed from observed generation.
    /// 5. `CoverageWitnessUncertified`: completeness or stop reason did not certify absence.
    /// 6. `NoCoverageWitness`: no coverage witness registered for domain.
    ///
    /// Canonical precedence rationale:
    /// - `CoverageRegistryCapacityExceeded` (fail-closed, global): while
    ///   [`Self::coverage_registry_at_capacity`] holds, a later witness for any domain, possibly
    ///   one reporting a continuity gap or an exclusion, would be refused. Absence therefore
    ///   cannot be certified for any domain, including domains no refused witness named. This
    ///   trades per-domain precision for exact rebuild: the condition is derived from canonical
    ///   history alone, never from a side record of refusals.
    /// - `CoverageWitnessGapped` (physical continuity failure): under AGENTS.md, treating missing
    ///   detection during a coverage gap as absence is strictly prohibited. Continuity breach
    ///   invalidates any claim of absence regardless of whether the domain was also excluded
    ///   or uncertified.
    /// - `ExcludedDomain` (explicit spatial/logical exclusion): if continuity was preserved,
    ///   but the domain was explicitly excluded from monitoring scope, no observation occurred.
    /// - `GenerationMismatch` (authority/configuration drift): the sensor observed under an
    ///   unapproved or stale generation (`authorized_generation != observed_generation` or 0).
    /// - `CoverageWitnessUncertified` (completeness / stop-reason deficit): the sensor observed
    ///   continuously on the authorized generation without excluding the domain, but completed
    ///   with partial completeness, a non-Complete stop reason, or did not certify absence.
    /// - `NoCoverageWitness`: no witness was registered for the requested domain.
    ///
    /// Every applicable reason is listed once, in this order, independent of registration order.
    /// If `domain` is empty or reserved unknown, returns `[UnknownDomain]`: such a query names no
    /// domain that any witness could cover, at capacity or not.
    /// If all matching witnesses certify absence and no non-observability conditions apply,
    /// returns an empty vector.
    #[must_use]
    pub fn coverage_non_observability_reasons(&self, domain: &str) -> Vec<NotObservableReason> {
        match self.evaluate_coverage(domain) {
            CoverageOutcome::Absent(_) => Vec::new(),
            CoverageOutcome::NotObservable { all_reasons, .. } => all_reasons,
        }
    }

    /// Evaluates coverage-for-absence for `domain` over every registered witness observing it.
    ///
    /// Absence is certified only when the store is below capacity, at least one witness observes
    /// the domain, and every such witness certifies absence; any single non-certifying witness
    /// wins (any-gap-wins). The result does not depend on witness registration order.
    fn evaluate_coverage(&self, domain: &str) -> CoverageOutcome<'_> {
        if is_unknown_domain(domain) {
            return CoverageOutcome::NotObservable {
                reason: NotObservableReason::UnknownDomain,
                all_reasons: vec![NotObservableReason::UnknownDomain],
            };
        }

        // Global fail-closed capacity rule; see `MAX_STORE_COVERAGE_WITNESSES`. It applies to
        // every domain, and it is derived only from history-backed counts, so the live and the
        // rebuilt store agree exactly.
        let at_capacity = self.coverage_registry_at_capacity();

        // fss-qlaao: domains named by a witness refused while the registry was at capacity stay
        // blocked even after a rotation sealed the registry. The refused report never entered
        // canonical custody, so the observation record for the domain is incomplete by
        // construction and absence can never be certified across it. Treated as a continuity
        // gap: the refusal names a coverage report the store could not admit.
        let refused_blocks = self
            .rotated_refused
            .iter()
            .any(|w| w.observed_domain.iter().any(|d| d == domain));

        let matching: Vec<&CoverageWitness> = self
            .coverage_witnesses
            .iter()
            .filter(|w| w.observed_domain.iter().any(|d| d == domain))
            .collect();

        // With no live witness there is nothing to certify from; the reasons are fixed here, so
        // the certifying branch below always has a non-empty witness set to choose from.
        let Some((first, rest)) = matching.split_first() else {
            let (reason, all_reasons) = if at_capacity {
                (
                    NotObservableReason::CoverageRegistryCapacityExceeded,
                    NotObservableReason::CoverageRegistryCapacityExceeded,
                )
            } else if refused_blocks {
                (
                    NotObservableReason::CoverageWitnessGapped,
                    NotObservableReason::CoverageWitnessGapped,
                )
            } else {
                (
                    NotObservableReason::NoCoverageWitness,
                    NotObservableReason::NoCoverageWitness,
                )
            };
            return CoverageOutcome::NotObservable {
                reason,
                all_reasons: vec![all_reasons],
            };
        };

        let mut reasons = Vec::with_capacity(5);

        if at_capacity {
            reasons.push(NotObservableReason::CoverageRegistryCapacityExceeded);
        }

        if refused_blocks {
            reasons.push(NotObservableReason::CoverageWitnessGapped);
        }

        if matching
            .iter()
            .any(|w| w.continuity != CoverageContinuity::Continuous)
        {
            reasons.push(NotObservableReason::CoverageWitnessGapped);
        }

        if matching
            .iter()
            .any(|w| w.excluded_domain.iter().any(|d| d == domain))
        {
            reasons.push(NotObservableReason::ExcludedDomain {
                domain: domain.to_string(),
            });
        }

        if let Some(mismatched) = matching
            .iter()
            .filter(|w| {
                w.authorized_generation == 0 || w.authorized_generation != w.observed_generation
            })
            .min_by_key(|w| {
                (
                    w.authorized_generation,
                    w.observed_generation,
                    w.witness_digest(),
                )
            })
        {
            reasons.push(NotObservableReason::GenerationMismatch {
                expected: mismatched.authorized_generation,
                observed: mismatched.observed_generation,
            });
        }

        if matching.iter().any(|w| {
            w.completeness != Completeness::Complete
                || w.stop_reason != CoverageStopReason::Complete
                || w.negative_predicate.trim().is_empty()
                || w.authorized_domain != w.observed_domain
                || (w.continuity == CoverageContinuity::Continuous
                    && !w.excluded_domain.iter().any(|d| d == domain)
                    && w.authorized_generation > 0
                    && w.authorized_generation == w.observed_generation
                    && !w.certifies_absence())
        }) {
            reasons.push(NotObservableReason::CoverageWitnessUncertified);
        }

        match reasons.first() {
            Some(primary) => CoverageOutcome::NotObservable {
                reason: primary.clone(),
                all_reasons: reasons,
            },
            // Every matching witness certifies absence and the store is below capacity.
            // Deterministically select the witness with the lowest digest.
            None => CoverageOutcome::Absent(rest.iter().copied().fold(*first, |best, w| {
                if w.witness_digest() < best.witness_digest() {
                    w
                } else {
                    best
                }
            })),
        }
    }
}

/// Outcome of one coverage-for-absence evaluation, projected onto each read result type.
///
/// Carrying no `Found` case lets every read path project it without an unreachable arm.
enum CoverageOutcome<'a> {
    /// Every matching witness certifies absence; this is the canonical certifying witness.
    Absent(&'a CoverageWitness),
    /// Absence cannot be certified.
    NotObservable {
        /// Primary reason under canonical precedence (the first of `all_reasons`).
        reason: NotObservableReason,
        /// Every applicable reason in canonical precedence order.
        all_reasons: Vec<NotObservableReason>,
    },
}

impl<'a> CoverageOutcome<'a> {
    fn into_event_read(self, domain: &str) -> EventReadResult<'a> {
        match self {
            Self::Absent(w) => EventReadResult::AbsentWithCoverage(w),
            Self::NotObservable {
                reason,
                all_reasons,
            } => EventReadResult::NotObservable {
                domain: domain.to_string(),
                reason,
                all_reasons,
            },
        }
    }

    fn into_lineage_read(self, domain: &str) -> LineageReadResult<'a> {
        match self {
            Self::Absent(w) => LineageReadResult::AbsentWithCoverage(w),
            Self::NotObservable {
                reason,
                all_reasons,
            } => LineageReadResult::NotObservable {
                domain: domain.to_string(),
                reason,
                all_reasons,
            },
        }
    }

    fn into_graph_read(self, domain: &str) -> GraphReadResult<'a> {
        match self {
            Self::Absent(w) => GraphReadResult::AbsentWithCoverage(w),
            Self::NotObservable {
                reason,
                all_reasons,
            } => GraphReadResult::NotObservable {
                domain: domain.to_string(),
                reason,
                all_reasons,
            },
        }
    }
}

fn compute_state_root(
    previous_root: ContentDigest,
    commit_sequence: u64,
    entry_digest: ContentDigest,
) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(EVENT_STORE_STATE_DOMAIN);
    encoder.digest(previous_root);
    encoder.u64(commit_sequence);
    encoder.digest(entry_digest);
    ContentDigest::sha256(&encoder.finish())
}
