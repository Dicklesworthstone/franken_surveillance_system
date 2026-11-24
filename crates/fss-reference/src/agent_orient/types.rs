#![forbid(unsafe_code)]
//! Constants, request/response types, error types, and compact shared helpers for [`super`].

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    AgentView, BudgetVector, CanonicalEncode, CanonicalEncoder, ContentDigest, ContractError,
    EffectState, EventHypothesis, EventId, EventState, ExplainReceipt, KnowledgeCell,
    KnowledgeCellParams, KnowledgeState, LedgerAnchor, MissionId, ObjectiveContract, Obligation,
    ObligationId, ObligationState, OperationId, OperationReceipt, OrientProjection, PossibleWorld,
    PrincipalId, SensorTamperStatus, SessionId, SituationCapsule, TimestampNs,
};

use super::coverage::{CoverageAssessment, RetainedCoverage, RetainedSourceCoverage};
use super::historical_health::RetainedHistoricalHealth;
use super::learning::OrientLearningBrief;
use super::mission::{OrientMissionBrief, OrientMissionProgress};
use crate::ReferenceError;
use crate::agent_session::checkpoint::journal::supervision::SupervisionInventoryEntry;
use crate::deployment_session::trauma_guard::AntiPatternWarning;
use crate::doctor::DoctorVerdict;
use crate::ingest::source_coverage::RetainedAbsence;
use crate::situation_sections::ReferenceSituationPublication;

pub use super::constants::{
    AFFORDANCE_CLAIM_PREFIX, AFFORDANCE_DOCTOR, AFFORDANCE_EXPLAIN_PREFIX,
    AFFORDANCE_FINDING_PREFIX, AFFORDANCE_FOLLOW, AFFORDANCE_INVESTIGATE_PREFIX, AFFORDANCE_PLAN,
    AFFORDANCE_PLAN_PREFIX, AFFORDANCE_RECONCILE_PREFIX, AFFORDANCE_REORIENT,
    CAPABILITY_CASE_WRITE, CAPABILITY_DOCTOR, CAPABILITY_EXPLAIN, CAPABILITY_PLAN_COMMIT,
    CAPABILITY_PLAN_PREPARE, CAPABILITY_SITUATION_READ, CAPABILITY_WORK_CLAIM, CLAIM_COVERAGE,
    CLAIM_EFFECT_JOURNAL, CLAIM_EVENTS, CLAIM_IMPORTS, CLAIM_LEDGER_HEAD,
    DIRECT_EVENT_EXPANSION_LIMIT, MAX_DEPLOYMENT_EVENTS, ORIENT_DATA_CLASSES,
    SOURCE_CLASS_EVENT_DETAIL, SOURCE_CLASS_WORLD_DETAIL, UNBOUND_SESSION_DEGRADATION,
    WORLD_EVENTS_PREFIX, WORLD_PROTECTED_SUMMARY, WORLD_UNOBSERVED_ACTIVITY,
};

/// Bounds applied while reading one deployment root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrientLimits {
    /// Maximum bytes read from `LAYOUT`.
    pub max_layout_bytes: usize,
    /// Maximum bytes read from one journal (ledger or effects).
    pub max_journal_bytes: usize,
    /// Maximum payload bytes of one spool object.
    pub max_object_bytes: usize,
    /// Maximum published events projected into one capsule.
    pub max_events: usize,
    /// Maximum committed revisions read back per event.
    pub max_revisions_per_event: usize,
}

impl Default for OrientLimits {
    fn default() -> Self {
        Self {
            max_layout_bytes: crate::doctor::MAX_LAYOUT_BYTES,
            max_journal_bytes: 64 * 1024 * 1024,
            max_object_bytes: 16 * 1024 * 1024,
            max_events: MAX_DEPLOYMENT_EVENTS,
            max_revisions_per_event: 64,
        }
    }
}

/// Why a deployment root could not be read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeploymentReadError {
    /// The root is missing, not a directory, or has no parseable `LAYOUT`.
    NotADeployment {
        /// Deterministic, secret-free reason.
        reason: String,
    },
    /// The root or one of its files could not be read.
    Unreadable {
        /// Deterministic, secret-free reason.
        reason: String,
    },
    /// Committed history failed replay or integrity verification.
    Corrupt {
        /// Deterministic, secret-free reason.
        reason: String,
    },
    /// The requested position is not a committed prefix of the root's history.
    NotCommitted {
        /// Deterministic, secret-free reason.
        reason: String,
    },
}

impl std::fmt::Display for DeploymentReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for DeploymentReadError {}

impl From<crate::deletion::DeletionError> for DeploymentReadError {
    fn from(value: crate::deletion::DeletionError) -> Self {
        corrupt(format!("deletion record: {value}"))
    }
}

impl DeploymentReadError {
    /// Human-readable reason.
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::NotADeployment { reason }
            | Self::Unreadable { reason }
            | Self::Corrupt { reason }
            | Self::NotCommitted { reason } => reason,
        }
    }
}

pub(super) fn corrupt(reason: impl Into<String>) -> DeploymentReadError {
    DeploymentReadError::Corrupt {
        reason: reason.into(),
    }
}

/// One published event lineage read back from the committed ledger and the object spool.
#[derive(Clone, Debug, PartialEq)]
pub struct RetainedEvent {
    /// Latest committed revision.
    pub event: EventHypothesis,
    /// Every committed revision, oldest first.
    pub revisions: Vec<EventHypothesis>,
    /// Published manifest root of the latest revision (the `event_revision` delta payload).
    pub event_root: ContentDigest,
    /// Revision digest witnessed by the latest `event_revision` delta.
    pub revision_digest: ContentDigest,
    /// Commit sequence that published the latest revision.
    pub committed_sequence: u64,
    /// Lineage sensor-tamper status recomputed from every committed revision.
    pub tamper: SensorTamperStatus,
    /// Spool bytes read (and rehashed) for this lineage's manifests and revisions: the exact
    /// source-evidence (H3) size of the event.
    pub object_bytes: u64,
    /// Spool objects read for this lineage.
    pub object_reads: u64,
}

impl RetainedEvent {
    /// Distinct failure domains named by the latest revision's evidence edges.
    #[must_use]
    pub fn failure_domains(&self) -> BTreeSet<String> {
        self.event
            .evidence
            .iter()
            .filter(|edge| !edge.failure_domain.is_empty())
            .map(|edge| edge.failure_domain.clone())
            .collect()
    }

    /// Whether the committed lifecycle state is independent corroboration.
    #[must_use]
    pub fn corroborated(&self) -> bool {
        self.event.state == EventState::Corroborated
    }
}

/// One committed authority position of a deployment: the authority-ledger prefix through a commit
/// sequence and the durable effect-journal prefix through a record count.
///
/// Both journals are append-only, so a position names exactly one earlier state of the root; a
/// snapshot at a position reads only the committed records inside it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HistoryPosition {
    /// Commit sequence of the last ledger batch in the prefix (0 before any commit).
    pub commit_sequence: u64,
    /// Committed effect-journal records in the prefix, or `None` when no effect journal existed.
    pub effect_records: Option<u64>,
}

/// Complete read-only snapshot of one deployment root at one committed position (by default its
/// head).
#[derive(Clone, Debug, PartialEq)]
pub struct DeploymentSnapshot {
    /// Site lineage from `LAYOUT`.
    pub site_lineage: String,
    /// Read-only doctor verdict when inspected; otherwise the conservative attention sentinel.
    pub doctor_verdict: DoctorVerdict,
    /// Whether the full read-only spool doctor actually ran. Metadata-only reads leave this
    /// false and cannot claim whole-spool health or source-payload verification.
    pub doctor_inspected: bool,
    /// Committed authority position this snapshot was compiled at.
    pub position: HistoryPosition,
    /// Committed authority anchor at [`Self::position`].
    pub anchor: LedgerAnchor,
    /// Root of the last committed ledger record in the prefix (zero when nothing is committed).
    pub ledger_root: ContentDigest,
    /// Committed evidence batches in the prefix.
    pub batch_count: usize,
    /// Record root of the last committed batch in the prefix that published an event revision
    /// (`None` when no event was published). The ledger record chain makes it cover every
    /// earlier event revision, and it does not move when an unrelated batch commits.
    pub event_ledger_root: Option<ContentDigest>,
    /// Record root of the last committed batch in the prefix that retained source evidence
    /// (`sensor_capsule`) or coverage (`coverage_witness`) (`None` when none did); like
    /// [`Self::event_ledger_root`] it does not move when an unrelated batch commits.
    pub evidence_ledger_root: Option<ContentDigest>,
    /// Record root of the last committed batch in the prefix that completed a file import
    /// (`file_import_manifest`) (`None` when none did).
    pub import_ledger_root: Option<ContentDigest>,
    /// Whether the ledger file ends with an incomplete or foreign tail beyond its committed
    /// records, as read now.
    pub ledger_tail_uncommitted: bool,
    /// Committed evidence deltas by family.
    pub family_counts: BTreeMap<String, usize>,
    /// Payload roots of completed file imports (`file_import_manifest` deltas) that no committed
    /// deletion removed.
    pub completed_imports: Vec<ContentDigest>,
    /// Deletion records committed at or before [`Self::position`] (a deletion is a change of the
    /// imports claim, never folded into silence).
    pub deletions_committed: usize,
    /// Whether the durable effect journal existed at [`Self::position`].
    pub effect_journal_present: bool,
    /// Digest of the committed effect-journal prefix at [`Self::position`] (the empty digest when
    /// absent).
    pub effect_journal_digest: ContentDigest,
    /// Root of the last committed effect-journal record in the prefix (zero when none).
    pub effect_journal_root: ContentDigest,
    /// Whether the effect journal file ends with an incomplete or foreign tail, as read now.
    pub effect_tail_uncommitted: bool,
    /// Durable obligations in journal order.
    pub obligations: Vec<Obligation>,
    /// Durable operation receipts in journal order.
    pub operations: Vec<OperationReceipt>,
    /// Published events in event-identity order.
    pub events: Vec<RetainedEvent>,
    /// Independent historical heuristic diagnostics in receipt-digest order. Reading this
    /// metadata does not rerun perception or establish current sensor health or coverage.
    pub historical_health: Vec<RetainedHistoricalHealth>,
    /// Latest verified network observations, each pinned to its retained sweep window.
    pub sensor_liveness: Vec<crate::discovery::retained_liveness::RetainedSensorLiveness>,
    /// Retained coverage records in commit order.
    pub coverage: Vec<RetainedCoverage>,
    /// Retained source coverage records (live or virtual sources, fss-tch7u) in commit order,
    /// each with its verdict under the stored-witness rule at this position.
    pub source_coverage: Vec<RetainedSourceCoverage>,
    /// Rejected events whose absence a stored witness certifies at this position, by event
    /// identity, with the record that is the stated reason.
    pub retained_absences: BTreeMap<String, RetainedAbsence>,
    /// Newest capture instant of each sensor's retained evidence that could postdate a coverage
    /// analysis (read only when coverage is retained).
    pub sensor_newest_evidence: BTreeMap<String, TimestampNs>,
    /// Whether newer evidence exceeded [`super::MAX_COVERAGE_CAPSULE_READS`] and was not attributed.
    pub coverage_evidence_unattributed: bool,
    /// Latest committed evidence time; the capsule creation time (0 when nothing is committed).
    pub latest_evidence_time: TimestampNs,
    /// Committed deletions of the whole history (custody is a fact about now): digests they
    /// name resolve to the `deleted` availability, never to a missing object.
    pub deletions: crate::deletion::DeletionIndex,
    /// Files a read of this position opens (all reads are bounded; none is opened for writing):
    /// `LAYOUT`, the ledger, the effect journal when present, and every spool object read back.
    pub files_read: u64,
    /// Bytes of those files inside the position: `LAYOUT`, the committed ledger and effect-journal
    /// prefixes, and the rehashed spool objects.
    pub bytes_read: u64,
}

impl DeploymentSnapshot {
    /// Obligations whose terminal predicate is not yet proved (pending or indeterminate).
    #[must_use]
    pub fn open_obligations(&self) -> Vec<&Obligation> {
        self.obligations
            .iter()
            .filter(|obligation| {
                matches!(
                    obligation.state,
                    ObligationState::Pending | ObligationState::Indeterminate
                )
            })
            .collect()
    }

    /// Operations whose external outcome is unresolved.
    #[must_use]
    pub fn indeterminate_operations(&self) -> Vec<&OperationReceipt> {
        self.operations
            .iter()
            .filter(|operation| operation.state == EffectState::Indeterminate)
            .collect()
    }

    /// Finds one published event by identity.
    #[must_use]
    pub fn event(&self, event_id: &EventId) -> Option<&RetainedEvent> {
        self.events
            .iter()
            .find(|retained| retained.event.event_id == *event_id)
    }
}

/// Stable spelling of an obligation state.
#[must_use]
pub const fn obligation_state_str(state: ObligationState) -> &'static str {
    match state {
        ObligationState::Pending => "pending",
        ObligationState::Verified => "verified",
        ObligationState::Failed => "failed",
        ObligationState::Indeterminate => "indeterminate",
        ObligationState::Cancelled => "cancelled",
    }
}

/// One read-only orient request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrientRequest {
    /// Registered view (`pulse`, `brief`, or `epistemic_map`).
    pub view: AgentView,
    /// Requesting principal (an audit label; no authority is minted).
    pub principal: PrincipalId,
    /// Explicit context-token budget; `None` admits at the view's registered target, falling back
    /// to the registered maximum with an explicit degradation.
    pub budget_tokens: Option<u64>,
}

impl OrientRequest {
    /// Canonical digest of this request at `anchor`: the response's request identity and the
    /// objective contract's source digest.
    #[must_use]
    pub fn digest_at(&self, anchor: &LedgerAnchor) -> ContentDigest {
        digest_of("fss.reference_orient_request.v1", |encoder| {
            encoder.text(self.view.id());
            self.principal.encode_canonical(encoder);
            encoder.u64(self.budget_tokens.unwrap_or(0));
            anchor.encode_canonical(encoder);
        })
    }
}

/// Views that carry the per-event knowledge cells of their top-ranked events inline; every other
/// event is summarized by [`CLAIM_EVENTS`] and the per-state boundaries (and stays hydratable).
/// Events carrying contradicting evidence or open sensor tamper are always inline. `brief` and
/// `epistemic_map` also list the explanation of the highest-consequence event.
#[must_use]
pub const fn inline_event_budget(view: AgentView) -> usize {
    match view {
        AgentView::EpistemicMap => 2,
        _ => 0,
    }
}

/// One ranked item of the orientation's attention frontier.
#[derive(Clone, Debug, PartialEq)]
pub struct AttentionItem {
    /// Stable item identity.
    pub item_id: String,
    /// Item kind (`event`, `coverage_gap`, `obligation`, `indeterminate_effect`,
    /// `historical_sensor_health`, `sensor_liveness`).
    pub kind: &'static str,
    /// Registered priority class.
    pub priority_class: &'static str,
    /// Mission-scope membership: 1.0 for every item inside the orientation scope (the whole
    /// deployment). It is not a learned relevance score.
    pub mission_relevance: f64,
    /// Registered consequence severity (0..=5) of the highest protected world the item keeps
    /// live, as a number; not a calibrated probability.
    pub decision_impact: f64,
    /// Why the item needs attention.
    pub reason: String,
    /// Handle that hydrates the item.
    pub handle: String,
}

/// One assumption the orientation rests on, with the cheapest way to retire it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpistemicDebtItem {
    /// Stable debt identity.
    pub debt_id: String,
    /// The assumption.
    pub assumption: String,
    /// Why it is not yet discharged.
    pub deferred_reason: String,
    /// Decisions that depend on it.
    pub dependent_decisions: Vec<String>,
    /// Consequence if it is wrong.
    pub consequence_if_wrong: String,
    /// Cheapest discriminating test.
    pub cheapest_test: String,
    /// What should trigger a review.
    pub review_trigger: String,
}

/// Validity of an anchor-pinned orientation: it claims nothing beyond its anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrientValidity {
    /// The anchor's evidence time: no validity is claimed past the anchor (the read is pinned to
    /// the committed prefix, not to a wall-clock horizon).
    pub valid_until: TimestampNs,
    /// Observable changes that invalidate the orientation.
    pub invalidators: Vec<String>,
    /// Stable triggers that require a re-anchor.
    pub reanchor_required_on: Vec<String>,
}

/// Hydration slot of one published event: what it hydrates and its price.
#[derive(Clone, Debug, PartialEq)]
pub struct EventHydration {
    /// The event.
    pub event_id: EventId,
    /// Stable expansion slot (`fss://event/<id>/revision/<n>`).
    pub handle: String,
    /// Latest committed revision digest (the handle's subject).
    pub revision_digest: ContentDigest,
    /// Every per-event world the slot hydrates.
    pub world_ids: Vec<String>,
    /// The protected ones among them.
    pub protected_world_ids: Vec<String>,
    /// Whether the event's knowledge cells are inline in this view.
    pub cells_inline: bool,
    /// Knowledge cells the event contributes when inline.
    pub cell_count: usize,
    /// Knowledge state of the event's physical-presence claim.
    pub physical_state: KnowledgeState,
    /// Highest consequence severity among the event's protected worlds.
    pub consequence_severity: u8,
    /// One-line H0 synopsis (revision, lifecycle state, corroboration).
    pub summary: String,
    /// Conservative price of the H1 synopsis (`fss explain`): one full read-only deployment read
    /// answered under the `decision_diff` view maximum.
    pub synopsis_cost: BudgetVector,
    /// Exact H3 size: the event's retained, rehashed spool objects.
    pub source_cost: BudgetVector,
}

/// Why an orientation could not be compiled for a readable deployment.
#[derive(Debug)]
pub enum OrientError {
    /// The view is not an orientation view.
    UnsupportedView(AgentView),
    /// The critical context does not fit the admitted token budget.
    ContextBudgetExceeded {
        /// View requested.
        view: AgentView,
        /// Largest token budget tried.
        budget_tokens: u64,
    },
    /// More events are published than one capsule may project.
    TooManyEvents {
        /// Published event lineages.
        published: usize,
        /// Projection bound.
        maximum: usize,
    },
    /// A reference contract refused the compiled situation.
    Contract(ReferenceError),
}

impl From<ReferenceError> for OrientError {
    fn from(value: ReferenceError) -> Self {
        Self::Contract(value)
    }
}

impl From<ContractError> for OrientError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value.into())
    }
}

impl std::fmt::Display for OrientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedView(view) => {
                write!(f, "view {} is not an orientation view", view.name())
            }
            Self::ContextBudgetExceeded {
                view,
                budget_tokens,
            } => write!(
                f,
                "the critical context of view {} does not fit {budget_tokens} tokens",
                view.name()
            ),
            Self::TooManyEvents { published, maximum } => write!(
                f,
                "{published} published events exceed the per-capsule bound of {maximum}"
            ),
            Self::Contract(error) => write!(f, "situation contract refused: {error}"),
        }
    }
}

impl std::error::Error for OrientError {}

/// One compiled, verified, read-only orientation.
#[derive(Clone, Debug, PartialEq)]
pub struct DeploymentOrientation {
    /// Exact admitted lifecycle metadata for existing mission revision/deadline wire fields.
    /// The protected context always distinguishes current from historical assessments.
    pub mission_progress: Option<OrientMissionProgress>,
    /// View the orientation was compiled for.
    pub view: AgentView,
    /// Verified reference publication: capsule, resource state, control envelope, context pack,
    /// and compression receipt.
    pub publication: ReferenceSituationPublication,
    /// AOP-003 section projection of the capsule under the view's entry budget.
    pub projection: OrientProjection,
    /// Token budget the context pack was admitted under.
    pub target_tokens: u64,
    /// Open (pending or indeterminate) obligations.
    pub open_obligations: Vec<ObligationId>,
    /// Operations whose external outcome is unresolved.
    pub indeterminate_effects: Vec<OperationId>,
    /// Explicit degradations of this answer.
    pub degradation: Vec<String>,
    /// Warnings that must accompany the answer.
    pub warnings: Vec<String>,
    /// Claim identities carrying contradicting evidence.
    pub contradictions: Vec<String>,
    /// Most uncertain knowledge state among the frame's cells.
    pub epistemic_state: KnowledgeState,
    /// Resources requested for the answer.
    pub requested: BudgetVector,
    /// Resources consumed by the answer (reads and context tokens; time is not metered).
    pub consumed: BudgetVector,
    /// Canonical request digest ([`OrientRequest::digest_at`]).
    pub request_digest: ContentDigest,
    /// The read-only orientation objective this answer serves.
    pub objective: ObjectiveContract,
    /// Ranked attention frontier.
    pub attention: Vec<AttentionItem>,
    /// Assumptions the orientation rests on.
    pub epistemic_debt: Vec<EpistemicDebtItem>,
    /// Anchor-bound validity.
    pub validity: OrientValidity,
    /// Hydration slot of every published event, in consequence-rank order.
    pub hydration: Vec<EventHydration>,
    /// Highest-consequence unresolved event, when any is published.
    pub headline_event: Option<EventId>,
    /// Every world the deployment keeps live (per-event worlds plus deployment worlds), before
    /// class aggregation.
    pub candidate_world_count: usize,
    /// Per-event worlds represented by class aggregates in this capsule.
    pub aggregated_world_count: usize,
    /// Privacy policy generation the answer is projected under (the anchor's privacy epoch).
    pub privacy_generation_id: String,
    /// Plan digest of the latest committed deletion closure (`FSS-037`) in this snapshot, or
    /// `None` when no deletion closure has been committed at this anchor.
    pub latest_deletion_closure_id: Option<String>,
    /// Reusable anchor token of the committed position this orientation is pinned to: the
    /// `--since` argument of `fss follow` (see [`crate::agent_follow::AnchorToken`]).
    pub anchor_token: String,
    /// Per-zone coverage from retained witnesses; `None` when no coverage record is retained.
    pub coverage: Option<CoverageAssessment>,
    /// Open investigation cases of the bound mission (empty when no session is bound).
    pub active_investigations: Vec<String>,
    /// Active plans of the bound mission (empty when no session is bound).
    pub active_plans: Vec<String>,
    /// Non-terminal work claims (leases) of the bound mission (empty when no session is bound).
    pub active_claims: Vec<String>,
    /// Active (neither superseded nor withdrawn) findings of the bound mission.
    pub active_findings: Vec<String>,
    /// Complete authorized recovery metadata, without configuration, reports or source pins.
    /// Its protected summary participates in the capsule and decision fingerprint.
    /// Generation comparisons are relative to this capsule's anchor; the native inventory
    /// accessor instead compares them with the persisted live session's interpretation basis.
    pub supervision_inventory: Vec<SupervisionInventoryEntry>,
    /// False means inventory was unavailable to this projection, never observed empty.
    pub supervision_inventory_available: bool,
}

impl DeploymentOrientation {
    /// The compiled capsule.
    #[must_use]
    pub const fn capsule(&self) -> &SituationCapsule {
        &self.publication.situation.capsule
    }

    /// Proof roots of the publication, in digest order.
    #[must_use]
    pub fn proof_roots(&self) -> &BTreeSet<ContentDigest> {
        &self.publication.situation.proof_roots
    }
}

/// One open investigation case of the bound mission (`fss investigate`), as listed by a
/// session-bound orientation. Cases are cognition: listing one never executes a probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrientCaseBrief {
    /// Stable case identity.
    pub case_id: String,
    /// Registered lifecycle spelling (`draft`, `active`, `awaiting_evidence`, ...).
    pub state: String,
    /// Case revision number.
    pub revision: u64,
    /// Hypotheses whose disposition is still live.
    pub live_hypotheses: Vec<String>,
    /// True when the case basis anchor is not the session's anchor (rebase before any change).
    pub rebase_required: bool,
}

/// One published, not yet terminal plan of the bound mission (`fss plan`), as listed by a
/// session-bound orientation. Listing a plan never prepares or commits anything.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrientPlanBrief {
    /// Stable plan identity.
    pub plan_id: String,
    /// Effect operation the plan prepares and commits.
    pub operation_id: String,
    /// Registered effect state of that operation, or `None` while it is not prepared.
    pub state: Option<String>,
}

/// The durable agent session and mission an orientation is compiled for (`fss session`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrientSessionBinding {
    /// Durable mission identity.
    pub mission_id: MissionId,
    /// Durable session identity.
    pub session_id: SessionId,
    /// Exact immutable requested mission admitted from this session's retained record.
    /// `None` leaves mission completion explicitly unassessed.
    pub mission: Option<OrientMissionBrief>,
    /// Exact retained execution-objective revision, with freshness verified by its native owner.
    /// Historical revisions remain visible but cannot assert a current terminal mission state.
    pub mission_progress: Option<OrientMissionProgress>,
    /// Open investigation cases of the mission visible to the session, in identity order.
    pub cases: Vec<OrientCaseBrief>,
    /// Active (non-terminal) plans of the mission, in identity order.
    pub plans: Vec<OrientPlanBrief>,
    /// Non-terminal work claims of the mission visible to the session, in identity order.
    pub claims: Vec<OrientClaimBrief>,
    /// Active findings of the mission, in identity order.
    pub findings: Vec<OrientFindingBrief>,
    /// Authenticated current session metadata. `Some([])` is an observed empty inventory;
    /// `None` means it was not admitted or loaded and cannot support an absence claim.
    pub supervisions: Option<Vec<SupervisionInventoryEntry>>,
    /// Verified advisory history visible to this principal. `None` is unavailable, not empty.
    /// These records cannot authorize effects or establish present physical facts.
    pub trauma_warnings: Option<Vec<AntiPatternWarning>>,
    /// Complete admitted captured-learning metadata for this exact session and mission.
    /// None is unavailable; Some(empty) alone is a successfully observed empty inventory.
    pub captured_learning: Option<Vec<OrientLearningBrief>>,
}

/// One active finding as a session-bound orientation lists it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrientFindingBrief {
    /// Stable finding identity.
    pub finding_id: String,
    /// The case it is about.
    pub case_id: String,
    /// Active findings in explicit disagreement with it.
    pub disputed_by: Vec<String>,
}

/// One non-terminal work claim (a coordination lease) as a session-bound orientation lists it.
/// Listing a claim grants nothing: work claims coordinate cognition and never confer effect
/// authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrientClaimBrief {
    /// Stable claim identity.
    pub claim_id: String,
    /// Case the claimed work belongs to.
    pub case_id: String,
    /// Registered claim state (`claimed`, `active`, or `blocked`).
    pub state: String,
    /// Session that holds the lease.
    pub owner_session: String,
    /// Lease expiry on the deployment evidence clock.
    pub expires_at: TimestampNs,
    /// Whether the lease still covers the evidence clock.
    pub lease_live: bool,
    /// Whether the orienting session holds the lease.
    pub held_here: bool,
}

/// One read-only explanation of a published event (AOP-011): the H1 synopsis behind the event's
/// hydration handle.
#[derive(Clone, Debug, PartialEq)]
pub struct EventExplanation {
    /// The retained event lineage explained.
    pub event: RetainedEvent,
    /// Bounded explain receipt binding the question, the event revision, and its evidence.
    pub receipt: ExplainReceipt,
    /// The event's knowledge cells, compiled exactly as an inline capsule carries them.
    pub cells: Vec<KnowledgeCell>,
    /// Every per-event world (the members its orientation aggregates).
    pub worlds: Vec<PossibleWorld>,
    /// Identities of the worlds that are adversarial residuals (the rest are material
    /// alternatives).
    pub residual_ids: BTreeSet<String>,
    /// Listed (never executed) next moves: this event's explanation and the re-orient heartbeat.
    pub affordances: Vec<fss_core::ActionAffordance>,
    /// Identities of [`Self::affordances`], sorted.
    pub next_actions: Vec<String>,
    /// Observations that would change the event's knowledge state.
    pub would_change: Vec<String>,
    /// Assumptions the explanation rests on.
    pub assumptions: Vec<String>,
    /// Warnings that must accompany the answer.
    pub warnings: Vec<String>,
    /// The event's hydration slot (handle and prices).
    pub hydration: EventHydration,
}

/// Only an authenticated workspace owner can compile the protected context of an AOP-006 Case.
/// Public AOP-003 entrypoints retain their original closed view profile.
#[derive(Clone, Copy)]
pub(super) enum ProjectionPurpose {
    Orientation,
    AdmittedWorkspace,
    AdmittedProbe,
}

pub(super) const fn severity_rank(state: KnowledgeState) -> u8 {
    match state {
        KnowledgeState::Conflicted => 8,
        KnowledgeState::Indeterminate => 7,
        KnowledgeState::NotObservable => 6,
        KnowledgeState::Unknown => 5,
        KnowledgeState::Stale => 4,
        KnowledgeState::Redacted => 3,
        KnowledgeState::Estimated => 2,
        KnowledgeState::Known => 1,
        KnowledgeState::NotApplicable => 0,
    }
}

/// A compact identity label: the first 128 bits (32 hex digits) of a digest. Every context item
/// repeats the frame, envelope, and deployment identities in its basis, so their length is paid
/// once per item under the view budget; the full digests stay published (frame digest, envelope
/// digest, decision fingerprint), and a 128-bit label keeps collisions out of reach.
pub(super) fn short_identity(value: ContentDigest) -> String {
    let text = value.to_text();
    let hex = text.split_once(':').map_or(text.as_str(), |(_, hex)| hex);
    hex.chars().take(32).collect()
}

pub(super) fn digest_of(domain: &str, parts: impl FnOnce(&mut CanonicalEncoder)) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(domain);
    parts(&mut encoder);
    ContentDigest::sha256(&encoder.finish())
}

pub(super) fn cell(params: KnowledgeCellParams) -> Result<KnowledgeCell, ContractError> {
    KnowledgeCell::new(params)?.validated()
}

pub(super) fn read_cost(
    bytes: u64,
    storage_operations: u64,
) -> Result<BudgetVector, ContractError> {
    BudgetVector::builder()
        .bytes(bytes)
        .storage_operations(storage_operations)
        .build()
        .map_err(|_| ContractError::BudgetExhausted)
}

pub(super) fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

pub(super) fn event_claim(event: &EventId, suffix: &str) -> String {
    format!("claim:event:{}:{suffix}", event.as_str())
}
