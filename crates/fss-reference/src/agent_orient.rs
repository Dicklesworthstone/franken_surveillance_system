#![forbid(unsafe_code)]
//! Read-only deployment orientation (AOP-003 `session.orient`) and event explanation
//! (AOP-011 `explain`) over an existing reference deployment root.
//!
//! [`read_deployment`] never writes, creates, locks, truncates, renames, fsyncs, or repairs
//! anything under the root. It classifies the root with the read-only [`crate::doctor`], parses
//! `LAYOUT` with a bound, replays the committed authority ledger prefix through
//! [`fss_ledger::inspect_durable`], replays the durable effect journal through
//! [`DurableEffectJournal::inspect`], and reads each published event revision back from the
//! object spool through [`fss_publication::read_verified`], which rehashes every payload.
//!
//! [`orient_deployment`] compiles one anchor-pinned [`SituationCapsule`] from that snapshot and
//! projects it through the same [`project_reference_situation`] selector every reference
//! publication uses, so the resource state, categorized control envelope, bounded context pack,
//! and semantic compression receipt are the verified reference sections. Nothing is invented:
//! an empty deployment yields `not_observable`/`unknown` cells and no event facts, and a published
//! watch candidate stays exactly as indeterminate, single-sensor, and uncorroborated as its
//! committed revision says. Affordances are listed with their operation, class, capability, and
//! cost; none is ever executed here.
//!
//! Views scale by compact encoding, never by truncation: events are ranked by consequence, a view
//! carries the per-event cells of its top-ranked events (and of every contradicted or tampered
//! event) inline and summarizes the rest in [`CLAIM_EVENTS`], and every per-event world is
//! aggregated into one world per kind that keeps the kind's maximum severity and protection
//! (pulse folds them further into [`WORLD_PROTECTED_SUMMARY`]). Each published event keeps one
//! stable, priced expansion slot in the compression receipt naming every world it hydrates, and
//! [`explain_event`] is its H1 hydration.
//!
//! Every output is a pure function of the committed bytes: the capsule time is the latest
//! committed evidence time, not the wall clock, so the same root yields identical output.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;

use fss_core::{
    ActionAffordance, AffordanceClass, AgentView, BudgetVector, CanonicalDecode, CanonicalEncode,
    CanonicalEncoder, Completeness, CompressionLossClass, CompressionTransform,
    CompressionTransformKind, ContentDigest, ContractError, EffectState, EventHypothesis, EventId,
    EventState, ExpansionHandle, ExplainQuestion, ExplainReceipt, KnowledgeCell,
    KnowledgeCellParams, KnowledgeState, LedgerAnchor, MissionId, ObjectiveContract,
    ObjectiveContractParams, ObjectiveScope, Obligation, ObligationId, ObligationState,
    OperationId, OperationReceipt, OrientBudget, OrientProjection, PossibleWorld, PrincipalId,
    ProvenanceClass, ResourcePressure, SensorTamperStatus, SessionId, SituationCapsule,
    SituationFrame, TimestampNs, WorldEnvelope, orient_projection,
};
use fss_object::ObjectManifest;

use crate::ReferenceError;
use crate::doctor::{DoctorVerdict, inspect_deployment};
use crate::durable_effect::DurableEffectJournal;
use crate::reference_deployment::{
    DEPLOYMENT_LAYOUT_FILENAME, DeploymentLayout, FAMILY_EVENT_REVISION,
    FAMILY_FILE_IMPORT_MANIFEST,
};
use crate::situation::{
    physical_knowledge_state, physical_statement, policy_hypothesis, reconciliation_basis_for,
    sensor_integrity_cell,
};
use crate::situation_guard::ReferenceSituation;
use crate::situation_sections::{
    ReferenceProjectionSpec, ReferenceSituationPublication, SourceOmission, SourceOmissions,
    project_reference_situation_with_source_omissions,
};

/// Capability registry row that admits a situation read (AOP-003, AOP-004, AOP-009).
pub const CAPABILITY_SITUATION_READ: &str = "CAP-AGENT-SITUATION-READ-001";
/// Capability registry row that admits an explanation (AOP-011).
pub const CAPABILITY_EXPLAIN: &str = "CAP-AGENT-EXPLAIN-001";
/// Capability registry row that admits a diagnosis (AOP-014).
pub const CAPABILITY_DOCTOR: &str = "CAP-REPAIR-PREPARE-001";
/// Capability registry row that admits plan preparation (AOP-007).
pub const CAPABILITY_PLAN_PREPARE: &str = "CAP-AGENT-PLAN-PREPARE-001";
/// Capability registry row that admits an effect commit (AOP-008).
pub const CAPABILITY_PLAN_COMMIT: &str = "CAP-AGENT-PLAN-COMMIT-001";

/// Stable claim identity of the ledger-head cell.
pub const CLAIM_LEDGER_HEAD: &str = "claim:deployment:ledger-head";
/// Stable claim identity of the retained-import cell.
pub const CLAIM_IMPORTS: &str = "claim:deployment:imports";
/// Stable claim identity of the durable effect journal cell.
pub const CLAIM_EFFECT_JOURNAL: &str = "claim:deployment:effect-journal";
/// Stable claim identity of the site coverage cell.
pub const CLAIM_COVERAGE: &str = "claim:coverage:site";
/// Stable identity of the protected world that no retained evidence covers.
pub const WORLD_UNOBSERVED_ACTIVITY: &str = "world:site:unobserved-activity";
/// Affordance identity of re-orienting after the ledger head advances.
pub const AFFORDANCE_REORIENT: &str = "affordance:orient:reorient";
/// Affordance identity of the read-only deployment diagnosis.
pub const AFFORDANCE_DOCTOR: &str = "affordance:orient:doctor";
/// Affordance identity of the unexposed follow stream.
pub const AFFORDANCE_FOLLOW: &str = "affordance:orient:follow";
/// Affordance identity of the unexposed plan/commit path.
pub const AFFORDANCE_PLAN: &str = "affordance:orient:plan";
/// Affordance-identity prefix of one event explanation.
pub const AFFORDANCE_EXPLAIN_PREFIX: &str = "affordance:explain:";
/// Affordance-identity prefix of one unexposed effect reconciliation.
pub const AFFORDANCE_RECONCILE_PREFIX: &str = "affordance:reconcile:";
/// Stable claim identity of the published-event summary cell.
pub const CLAIM_EVENTS: &str = "claim:deployment:events";
/// World-identity prefix of one per-kind aggregate of per-event worlds.
pub const WORLD_EVENTS_PREFIX: &str = "world:events:";
/// The single protected world the pulse heartbeat folds every protected world into.
pub const WORLD_PROTECTED_SUMMARY: &str = "world:site:protected-worlds";
/// Source-omission class of per-event knowledge cells summarized out of a view.
pub const SOURCE_CLASS_EVENT_DETAIL: &str = "event_detail";
/// Source-omission class of per-event worlds represented by per-kind aggregates.
pub const SOURCE_CLASS_WORLD_DETAIL: &str = "protected_world_detail";

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
            max_events: 128,
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
}

impl std::fmt::Display for DeploymentReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for DeploymentReadError {}

impl DeploymentReadError {
    /// Human-readable reason.
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::NotADeployment { reason }
            | Self::Unreadable { reason }
            | Self::Corrupt { reason } => reason,
        }
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

/// Complete read-only snapshot of one deployment root at its committed ledger head.
#[derive(Clone, Debug, PartialEq)]
pub struct DeploymentSnapshot {
    /// Site lineage from `LAYOUT`.
    pub site_lineage: String,
    /// Read-only doctor verdict for the root.
    pub doctor_verdict: DoctorVerdict,
    /// Committed authority anchor (ledger head).
    pub anchor: LedgerAnchor,
    /// Root of the last committed ledger record (zero when nothing is committed).
    pub ledger_root: ContentDigest,
    /// Committed evidence batches.
    pub batch_count: usize,
    /// Whether the ledger ends with an incomplete or foreign tail beyond its committed prefix.
    pub ledger_tail_uncommitted: bool,
    /// Committed evidence deltas by family.
    pub family_counts: BTreeMap<String, usize>,
    /// Payload roots of completed file imports (`file_import_manifest` deltas).
    pub completed_imports: Vec<ContentDigest>,
    /// Whether the durable effect journal file exists.
    pub effect_journal_present: bool,
    /// Digest of the effect journal bytes that were inspected (the empty digest when absent).
    pub effect_journal_digest: ContentDigest,
    /// Whether the effect journal ends with an incomplete or foreign tail.
    pub effect_tail_uncommitted: bool,
    /// Durable obligations in journal order.
    pub obligations: Vec<Obligation>,
    /// Durable operation receipts in journal order.
    pub operations: Vec<OperationReceipt>,
    /// Published events in event-identity order.
    pub events: Vec<RetainedEvent>,
    /// Latest committed evidence time; the capsule creation time (0 when nothing is committed).
    pub latest_evidence_time: TimestampNs,
    /// Files opened for reading (all reads are bounded; none is opened for writing).
    pub files_read: u64,
    /// Bytes read from those files.
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

struct Reader {
    files_read: u64,
    bytes_read: u64,
}

impl Reader {
    /// Reads at most `max` bytes from a regular, non-symlink file; `Ok(None)` when absent.
    fn read_file(&mut self, path: &Path, max: usize) -> io::Result<Option<Vec<u8>>> {
        let meta = match fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if !meta.file_type().is_file() {
            return Err(io::Error::other("not a regular file"));
        }
        if meta.len() > max as u64 {
            return Err(io::Error::other("file exceeds its read bound"));
        }
        let mut bytes = Vec::new();
        File::open(path)?
            .take(max as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > max {
            return Err(io::Error::other("file exceeds its read bound"));
        }
        self.files_read += 1;
        self.bytes_read += bytes.len() as u64;
        Ok(Some(bytes))
    }

    fn read_object(
        &mut self,
        objects: &Path,
        digest: ContentDigest,
        max: usize,
    ) -> Result<Vec<u8>, DeploymentReadError> {
        let bytes = fss_publication::read_verified(objects, digest, max).map_err(|error| {
            DeploymentReadError::Corrupt {
                reason: format!("spool object {digest} is unavailable or corrupt: {error}"),
            }
        })?;
        self.files_read += 1;
        self.bytes_read += bytes.len() as u64;
        Ok(bytes)
    }
}

fn corrupt(reason: impl Into<String>) -> DeploymentReadError {
    DeploymentReadError::Corrupt {
        reason: reason.into(),
    }
}

/// Reads one deployment root without writing anything under it.
///
/// A missing root, a non-directory, or a root without a parseable `LAYOUT` is
/// [`DeploymentReadError::NotADeployment`]; an access failure is
/// [`DeploymentReadError::Unreadable`]; history that fails replay or rehash is
/// [`DeploymentReadError::Corrupt`]. An incomplete journal tail is not an error: only the
/// committed prefix is read, and the snapshot records that the tail exists.
pub fn read_deployment(
    root: &Path,
    limits: &OrientLimits,
) -> Result<DeploymentSnapshot, DeploymentReadError> {
    let doctor_verdict = inspect_deployment(root).verdict;
    match doctor_verdict {
        DoctorVerdict::NotADeployment => {
            return Err(DeploymentReadError::NotADeployment {
                reason: "the root is missing, is not a directory, or has no valid LAYOUT \
                         (see `fss doctor --json --root <dir>`)"
                    .to_owned(),
            });
        }
        DoctorVerdict::Unreadable => {
            return Err(DeploymentReadError::Unreadable {
                reason: "the deployment root or its LAYOUT cannot be read".to_owned(),
            });
        }
        DoctorVerdict::Healthy | DoctorVerdict::AttentionRequired => {}
    }
    let mut reader = Reader {
        files_read: 0,
        bytes_read: 0,
    };
    let layout_bytes = reader
        .read_file(
            &root.join(DEPLOYMENT_LAYOUT_FILENAME),
            limits.max_layout_bytes,
        )
        .map_err(|error| DeploymentReadError::Unreadable {
            reason: format!("LAYOUT: {error}"),
        })?
        .ok_or_else(|| DeploymentReadError::NotADeployment {
            reason: "missing LAYOUT".to_owned(),
        })?;
    let layout_text =
        String::from_utf8(layout_bytes).map_err(|_| DeploymentReadError::NotADeployment {
            reason: "LAYOUT is not UTF-8".to_owned(),
        })?;
    let layout = DeploymentLayout::parse_canonical_text(&layout_text).map_err(|error| {
        DeploymentReadError::NotADeployment {
            reason: format!("LAYOUT does not parse: {error}"),
        }
    })?;
    let site = layout.site_lineage.clone();
    let objects = root.join(&layout.objects_relpath);

    let ledger = fss_ledger::inspect_durable(
        root.join(&layout.ledger_relpath),
        site.clone(),
        limits.max_journal_bytes,
    )
    .map_err(|error| corrupt(format!("authority ledger replay failed: {error}")))?;
    reader.files_read += 1;
    reader.bytes_read += ledger.committed_len;

    let effects_path = root.join(&layout.effects_relpath);
    let effects = DurableEffectJournal::inspect(&effects_path, limits.max_journal_bytes)
        .map_err(|error| corrupt(format!("durable effect journal replay failed: {error}")))?;
    let effect_bytes = reader
        .read_file(&effects_path, limits.max_journal_bytes)
        .map_err(|error| DeploymentReadError::Unreadable {
            reason: format!("effect journal: {error}"),
        })?;
    let effect_journal_present = !effects.is_absent();
    let effect_journal_digest = ContentDigest::sha256(effect_bytes.as_deref().unwrap_or_default());
    let (obligations, operations) = match &effects.journal {
        Some(journal) => (
            journal.obligations().cloned().collect(),
            journal.operations().cloned().collect(),
        ),
        None => (Vec::new(), Vec::new()),
    };

    let mut family_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut completed_imports = Vec::new();
    let mut latest_evidence_time = TimestampNs::ZERO;
    // object id -> (generation -> (payload root, witnessed revision digest, commit sequence))
    let mut event_deltas: BTreeMap<String, BTreeMap<u64, (ContentDigest, ContentDigest, u64)>> =
        BTreeMap::new();
    for batch in &ledger.batches {
        for delta in &batch.deltas {
            *family_counts.entry(delta.family.clone()).or_default() += 1;
            if delta.validity.latest > latest_evidence_time {
                latest_evidence_time = delta.validity.latest;
            }
            if delta.family == FAMILY_FILE_IMPORT_MANIFEST {
                completed_imports.push(delta.payload_digest);
            }
            if delta.family == FAMILY_EVENT_REVISION {
                let witness = delta.witness_digest.ok_or_else(|| {
                    corrupt(format!(
                        "event_revision delta {} carries no revision witness",
                        delta.delta_id
                    ))
                })?;
                event_deltas
                    .entry(delta.object_id.as_str().to_owned())
                    .or_default()
                    .insert(
                        delta.new_generation,
                        (
                            delta.payload_digest,
                            witness,
                            batch.new_anchor.commit_sequence,
                        ),
                    );
            }
        }
    }

    let mut events = Vec::new();
    for (object_id, generations) in &event_deltas {
        if generations.len() > limits.max_revisions_per_event {
            return Err(corrupt(format!(
                "{object_id} has {} committed revisions, above the read bound {}",
                generations.len(),
                limits.max_revisions_per_event
            )));
        }
        let mut revisions = Vec::new();
        let mut latest = None;
        let (bytes_before, reads_before) = (reader.bytes_read, reader.files_read);
        for (generation, (root_digest, witness, sequence)) in generations {
            let manifest = ObjectManifest::from_canonical_bytes(&reader.read_object(
                &objects,
                *root_digest,
                limits.max_object_bytes,
            )?)
            .map_err(|error| corrupt(format!("{object_id}: manifest: {error}")))?;
            let payload = manifest
                .metadata_digest()
                .or_else(|| manifest.children().first().copied())
                .ok_or_else(|| corrupt(format!("{object_id}: event manifest names no payload")))?;
            let revision = EventHypothesis::from_canonical_bytes(&reader.read_object(
                &objects,
                payload,
                limits.max_object_bytes,
            )?)
            .map_err(|error| corrupt(format!("{object_id}: event revision: {error}")))?;
            if revision.revision != *generation || revision.revision_digest() != *witness {
                return Err(corrupt(format!(
                    "{object_id}: revision {generation} does not match its committed witness"
                )));
            }
            latest = Some((*root_digest, *witness, *sequence));
            revisions.push(revision);
        }
        let (Some(event), Some((event_root, revision_digest, committed_sequence))) =
            (revisions.last().cloned(), latest)
        else {
            continue;
        };
        let tamper = fss_core::event::compute_sensor_tamper_status(revisions.iter(), None);
        events.push(RetainedEvent {
            event,
            revisions,
            event_root,
            revision_digest,
            committed_sequence,
            tamper,
            object_bytes: reader.bytes_read - bytes_before,
            object_reads: reader.files_read - reads_before,
        });
    }
    events.sort_by(|left, right| left.event.event_id.cmp(&right.event.event_id));

    Ok(DeploymentSnapshot {
        site_lineage: site,
        doctor_verdict,
        anchor: ledger.snapshot.anchor.clone(),
        ledger_root: ledger.last_root,
        batch_count: ledger.batches.len(),
        ledger_tail_uncommitted: !ledger.is_clean(),
        family_counts,
        completed_imports,
        effect_journal_present,
        effect_journal_digest,
        effect_tail_uncommitted: effect_journal_present && !effects.is_clean(),
        obligations,
        operations,
        events,
        latest_evidence_time,
        files_read: reader.files_read,
        bytes_read: reader.bytes_read,
    })
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
    /// Item kind (`event`, `coverage_gap`, `obligation`, `indeterminate_effect`).
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

const fn severity_rank(state: KnowledgeState) -> u8 {
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
fn short_identity(value: ContentDigest) -> String {
    let text = value.to_text();
    let hex = text.split_once(':').map_or(text.as_str(), |(_, hex)| hex);
    hex.chars().take(32).collect()
}

fn digest_of(domain: &str, parts: impl FnOnce(&mut CanonicalEncoder)) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(domain);
    parts(&mut encoder);
    ContentDigest::sha256(&encoder.finish())
}

fn cell(params: KnowledgeCellParams) -> Result<KnowledgeCell, ContractError> {
    KnowledgeCell::new(params)?.validated()
}

fn read_cost(bytes: u64, storage_operations: u64) -> Result<BudgetVector, ContractError> {
    BudgetVector::builder()
        .bytes(bytes)
        .storage_operations(storage_operations)
        .build()
        .map_err(|_| ContractError::BudgetExhausted)
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

fn event_claim(event: &EventId, suffix: &str) -> String {
    format!("claim:event:{}:{suffix}", event.as_str())
}

/// Knowledge cells, worlds, and statements contributed by one published event.
struct EventSection {
    cells: Vec<KnowledgeCell>,
    alternatives: Vec<PossibleWorld>,
    residuals: Vec<PossibleWorld>,
    lifecycle_claim: String,
    unknown: Vec<String>,
    at_risk: Vec<String>,
    warnings: Vec<String>,
    proof_roots: Vec<ContentDigest>,
    /// Knowledge state of the event's physical-presence claim.
    physical_state: KnowledgeState,
    /// Whether any of the event's cells carries contradicting evidence.
    contradicted: bool,
}

impl EventSection {
    fn worlds(&self) -> impl Iterator<Item = &PossibleWorld> {
        self.alternatives.iter().chain(&self.residuals)
    }

    /// Highest consequence severity among the event's protected worlds.
    fn protected_severity(&self) -> u8 {
        self.worlds()
            .filter(|world| world.protected)
            .map(|world| world.consequence_severity)
            .max()
            .unwrap_or(0)
    }
}

fn event_section(retained: &RetainedEvent) -> Result<EventSection, ReferenceError> {
    let event = &retained.event;
    let id = &event.event_id;
    let lifecycle_claim = event_claim(id, "lifecycle");
    let physical_claim = event_claim(id, "unknown-presence");
    let corroboration_claim = event_claim(id, "corroboration");
    let supporting: Vec<_> = event
        .evidence
        .iter()
        .filter(|edge| edge.counts_as_support())
        .map(|edge| edge.digest)
        .collect();
    let contradicting: Vec<_> = event
        .evidence
        .iter()
        .filter(|edge| edge.counts_as_contradiction())
        .map(|edge| edge.digest)
        .collect();
    let domains = retained.failure_domains();
    let mut cells = vec![cell(KnowledgeCellParams {
        claim_id: lifecycle_claim.clone(),
        statement: format!(
            "Event {} is published at revision {} as kind {} in state {} (commit {}, zones [{}]).",
            id.as_str(),
            event.revision,
            event.kind.as_str(),
            event.state.as_str(),
            retained.committed_sequence,
            event.zone_ids.join(",")
        ),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![retained.event_root, retained.revision_digest],
        contradictions: Vec::new(),
        valid_until: None,
        state_basis: None,
    })?];

    let computed = physical_knowledge_state(event.state, &supporting, &contradicting);
    let physical_state = if retained.tamper.has_open_tamper() && computed == KnowledgeState::Known {
        KnowledgeState::Unknown
    } else {
        computed
    };
    cells.push(cell(KnowledgeCellParams {
        claim_id: physical_claim.clone(),
        statement: format!(
            "{} ({} candidate.)",
            physical_statement(event.state),
            event.kind.as_str()
        ),
        knowledge_state: physical_state,
        provenance: ProvenanceClass::Derived,
        hypothesis: Some(policy_hypothesis(event.state)),
        evidence: supporting.clone(),
        contradictions: contradicting.clone(),
        valid_until: None,
        state_basis: reconciliation_basis_for(physical_state, retained.revision_digest),
    })?);

    let corroborated = retained.corroborated();
    cells.push(cell(KnowledgeCellParams {
        claim_id: corroboration_claim,
        statement: if corroborated {
            format!(
                "Independent corroboration across {} is committed.",
                plural(domains.len(), "failure domain", "failure domains")
            )
        } else {
            format!(
                "Not corroborated: evidence names {} ([{}]); a single sensor cannot corroborate itself.",
                plural(domains.len(), "failure domain", "failure domains"),
                domains.iter().cloned().collect::<Vec<_>>().join(",")
            )
        },
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![retained.revision_digest],
        contradictions: Vec::new(),
        valid_until: None,
        state_basis: None,
    })?);
    if let Some(integrity) = sensor_integrity_cell(id.as_str(), event, &retained.tamper)? {
        cells.push(integrity);
    }

    let mut alternatives = Vec::new();
    let mut residuals = Vec::new();
    let mut unknown = Vec::new();
    let mut at_risk = Vec::new();
    let mut warnings = Vec::new();
    let world = |suffix: &str| format!("world:event:{}:{suffix}", id.as_str());
    match event.state {
        EventState::Corroborated => {
            alternatives.push(PossibleWorld {
                world_id: world("present"),
                description:
                    "The corroborated activity is physically present in the retained interval."
                        .to_owned(),
                claim_ids: BTreeSet::from([lifecycle_claim.clone(), physical_claim.clone()]),
                evidence: vec![retained.revision_digest],
                consequence_severity: 5,
                protected: true,
            });
            residuals.push(PossibleWorld {
                world_id: world("common-mode-error"),
                description: "The corroborating sources share a spoofing, failure, or environmental artifact.".to_owned(),
                claim_ids: BTreeSet::from([lifecycle_claim.clone()]),
                evidence: vec![retained.event_root],
                consequence_severity: 4,
                protected: true,
            });
        }
        EventState::Rejected => {
            alternatives.push(PossibleWorld {
                world_id: world("candidate-rejected"),
                description: "The candidate is rejected within the evaluated evidence.".to_owned(),
                claim_ids: BTreeSet::from([lifecycle_claim.clone()]),
                evidence: vec![retained.event_root],
                consequence_severity: 1,
                protected: false,
            });
            residuals.push(PossibleWorld {
                world_id: world("absence-uncertified"),
                description: "Activity outside the evaluated evidence remains possible; no CoverageWitness certifies absence.".to_owned(),
                claim_ids: BTreeSet::from([lifecycle_claim.clone(), CLAIM_COVERAGE.to_owned()]),
                evidence: vec![retained.revision_digest],
                consequence_severity: 5,
                protected: true,
            });
            unknown.push(format!(
                "Rejection of {} is not a certified negative read.",
                id.as_str()
            ));
        }
        EventState::Hypothesized
        | EventState::Witnessed
        | EventState::Indeterminate
        | EventState::Adjudicated
        | EventState::AlertDelivered
        | EventState::Resolved => {
            alternatives.push(PossibleWorld {
                world_id: world("activity-live"),
                description:
                    "Real activity in the named zone remains possible under the retained evidence."
                        .to_owned(),
                claim_ids: BTreeSet::from([lifecycle_claim.clone(), physical_claim.clone()]),
                evidence: vec![retained.revision_digest],
                consequence_severity: 5,
                protected: true,
            });
            residuals.push(PossibleWorld {
                world_id: world("artifact-live"),
                description:
                    "A benign, artifact, or erroneous detection explanation remains possible."
                        .to_owned(),
                claim_ids: BTreeSet::from([lifecycle_claim.clone()]),
                evidence: vec![retained.event_root],
                consequence_severity: 4,
                protected: true,
            });
            unknown.push(format!(
                "Whether {} reflects real activity is {}.",
                id.as_str(),
                physical_state.as_str()
            ));
        }
    }
    if !corroborated {
        warnings.push(format!(
            "{} is single-sensor and not corroborated; it grants no alert or effect authority.",
            id.as_str()
        ));
    }
    if !contradicting.is_empty() {
        unknown.push(format!(
            "{} carries {} contradicting evidence root(s).",
            id.as_str(),
            contradicting.len()
        ));
    }
    let tamper_roots = &retained.tamper.open_tamper_roots;
    if !tamper_roots.is_empty() {
        at_risk.push(format!(
            "Sensor tamper is reported for {} by {} retained root(s).",
            id.as_str(),
            tamper_roots.len()
        ));
        residuals.push(PossibleWorld {
            world_id: world("sensor-tamper"),
            description: "A contributing sensor is tampered with, so retained evidence may conceal or fabricate activity.".to_owned(),
            claim_ids: BTreeSet::from([lifecycle_claim.clone()]),
            evidence: tamper_roots.clone(),
            consequence_severity: 5,
            protected: true,
        });
    }
    let mut proof_roots = vec![retained.event_root, retained.revision_digest];
    proof_roots.extend(event.evidence.iter().map(|edge| edge.digest));
    proof_roots.extend(event.model_receipts.iter().copied());
    proof_roots.extend(tamper_roots.iter().copied());
    let contradicted = cells.iter().any(|cell| !cell.contradictions().is_empty());
    Ok(EventSection {
        cells,
        alternatives,
        residuals,
        lifecycle_claim,
        unknown,
        at_risk,
        warnings,
        proof_roots,
        physical_state,
        contradicted,
    })
}

/// One published event, compiled and ranked for a view.
struct PlannedEvent<'a> {
    retained: &'a RetainedEvent,
    section: EventSection,
    /// Whether the event's knowledge cells are inline in the view's capsule.
    inline: bool,
}

impl PlannedEvent<'_> {
    fn id(&self) -> &str {
        self.retained.event.event_id.as_str()
    }
}

/// Consequence order: highest protected severity, open tamper, unresolved, most recently
/// committed, then event identity (deterministic).
fn consequence_order(left: &PlannedEvent<'_>, right: &PlannedEvent<'_>) -> std::cmp::Ordering {
    let key = |event: &PlannedEvent<'_>| {
        (
            std::cmp::Reverse(event.section.protected_severity()),
            std::cmp::Reverse(event.retained.tamper.has_open_tamper()),
            std::cmp::Reverse(!matches!(
                event.retained.event.state,
                EventState::Resolved | EventState::Rejected
            )),
            std::cmp::Reverse(event.retained.committed_sequence),
        )
    };
    key(left)
        .cmp(&key(right))
        .then_with(|| left.id().cmp(right.id()))
}

fn planned_events<'a>(
    snapshot: &'a DeploymentSnapshot,
    view: AgentView,
) -> Result<Vec<PlannedEvent<'a>>, ReferenceError> {
    let mut planned = Vec::with_capacity(snapshot.events.len());
    for retained in &snapshot.events {
        planned.push(PlannedEvent {
            section: event_section(retained)?,
            retained,
            inline: false,
        });
    }
    planned.sort_by(consequence_order);
    let budget = inline_event_budget(view);
    for (rank, event) in planned.iter_mut().enumerate() {
        // Contradictions and open tamper are non-droppable: those events are always inline.
        event.inline =
            rank < budget || event.section.contradicted || event.retained.tamper.has_open_tamper();
    }
    Ok(planned)
}

/// Class key of one per-event world: `world:event:<id>:<kind>` → `<kind>`.
fn world_kind<'w>(world: &'w PossibleWorld, event: &str) -> &'w str {
    world
        .world_id
        .strip_prefix(&format!("world:event:{event}:"))
        .unwrap_or(world.world_id.as_str())
}

/// Aggregate of one world kind across events.
struct WorldClass {
    residual: bool,
    description: String,
    members: Vec<String>,
    severity: u8,
    protected: bool,
}

/// Aggregates every per-event world into one world per kind, preserving the maximum severity and
/// protection of its members.
fn aggregate_worlds(
    planned: &[PlannedEvent<'_>],
) -> (
    BTreeMap<String, WorldClass>,
    BTreeMap<String, BTreeSet<String>>,
) {
    let mut classes: BTreeMap<String, WorldClass> = BTreeMap::new();
    let mut memberships: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for event in planned {
        let lists = [
            (false, &event.section.alternatives),
            (true, &event.section.residuals),
        ];
        for (residual, worlds) in lists {
            for world in worlds {
                let kind = world_kind(world, event.id()).to_owned();
                let class_id = format!("{WORLD_EVENTS_PREFIX}{kind}");
                let class = classes
                    .entry(class_id.clone())
                    .or_insert_with(|| WorldClass {
                        residual,
                        description: world.description.clone(),
                        members: Vec::new(),
                        severity: 0,
                        protected: false,
                    });
                class.members.push(world.world_id.clone());
                class.severity = class.severity.max(world.consequence_severity);
                class.protected |= world.protected;
                memberships
                    .entry(event.id().to_owned())
                    .or_default()
                    .insert(class_id);
            }
        }
    }
    (classes, memberships)
}

/// `1 indeterminate, 2 rejected` over the latest committed revisions.
fn state_counts(planned: &[PlannedEvent<'_>]) -> String {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for event in planned {
        *counts
            .entry(event.retained.event.state.as_str())
            .or_default() += 1;
    }
    counts
        .iter()
        .map(|(state, count)| format!("{count} {state}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The capsule, its proof roots, and the answer metadata compiled before projection.
struct CompiledSituation {
    capsule: SituationCapsule,
    proof_roots: BTreeSet<ContentDigest>,
    degradation: Vec<String>,
    warnings: Vec<String>,
    source: SourceOmissions,
    hydration: Vec<EventHydration>,
    headline_event: Option<EventId>,
    candidate_world_count: usize,
    aggregated_world_count: usize,
    epistemic_state: KnowledgeState,
    contradictions: Vec<String>,
    attention: Vec<AttentionItem>,
    epistemic_debt: Vec<EpistemicDebtItem>,
}

fn compile_capsule(
    snapshot: &DeploymentSnapshot,
    request: &OrientRequest,
) -> Result<CompiledSituation, OrientError> {
    let heartbeat = request.view == AgentView::Pulse;
    let anchor = snapshot.anchor.clone();
    let site = snapshot.site_lineage.as_str();
    let site_digest = ContentDigest::sha256(site.as_bytes());
    let objective_id = format!("objective:orient:{site_digest}");
    let mission_id = MissionId::parse(format!("mission:orient:{site_digest}"))?;
    let session_id = SessionId::parse(format!(
        "session:orient:{}",
        digest_of("fss.reference_orient_session.v1", |encoder| {
            encoder.text(site);
            request.principal.encode_canonical(encoder);
        })
    ))?;
    let basis = fss_core::reference_contract_basis();
    let deployment_handle = format!("fss://deployment/{}", short_identity(site_digest));

    let mut degradation = vec![
        "No durable agent session exists (session.open is not exposed): this capsule is bound \
         to a deterministic read-only session identity and persists nothing."
            .to_owned(),
    ];
    let mut warnings = Vec::new();
    let mut unknown = Vec::new();
    let mut at_risk = Vec::new();
    let mut why = Vec::new();
    let mut proof_roots = BTreeSet::from([anchor.state_root, snapshot.effect_journal_digest]);
    let ledger_evidence = if snapshot.batch_count == 0 {
        anchor.state_root
    } else {
        proof_roots.insert(snapshot.ledger_root);
        snapshot.ledger_root
    };

    let planned = planned_events(snapshot, request.view)?;
    let headline = planned.first();

    // Deployment-state cells: exactly what the committed bytes establish.
    let families = if snapshot.family_counts.is_empty() {
        "none".to_owned()
    } else {
        snapshot
            .family_counts
            .iter()
            .map(|(family, count)| format!("{family}={count}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let known_cell = |claim: &str, statement: String, evidence: Vec<ContentDigest>| {
        cell(KnowledgeCellParams {
            claim_id: claim.to_owned(),
            statement,
            knowledge_state: KnowledgeState::Known,
            provenance: ProvenanceClass::Derived,
            hypothesis: None,
            evidence,
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        })
    };
    let mut cells = vec![
        known_cell(
            CLAIM_LEDGER_HEAD,
            format!(
                "The authority ledger holds {} at commit {} (ledger epoch {}); committed deltas: {families}.",
                plural(snapshot.batch_count, "committed batch", "committed batches"),
                anchor.commit_sequence,
                anchor.ledger_epoch
            ),
            vec![ledger_evidence],
        )?,
        known_cell(
            CLAIM_IMPORTS,
            format!(
                "{} retained at this anchor.",
                plural(
                    snapshot.completed_imports.len(),
                    "completed file import is",
                    "completed file imports are"
                )
            ),
            if snapshot.completed_imports.is_empty() {
                vec![ledger_evidence]
            } else {
                snapshot.completed_imports.clone()
            },
        )?,
        known_cell(
            CLAIM_EFFECT_JOURNAL,
            if snapshot.effect_journal_present {
                format!(
                    "The durable effect journal holds {} and {} ({} open).",
                    plural(snapshot.operations.len(), "operation", "operations"),
                    plural(snapshot.obligations.len(), "obligation", "obligations"),
                    snapshot.open_obligations().len()
                )
            } else {
                "No durable effect journal exists, so no effect was ever prepared.".to_owned()
            },
            vec![snapshot.effect_journal_digest],
        )?,
        cell(KnowledgeCellParams {
            claim_id: CLAIM_COVERAGE.to_owned(),
            statement: "No CoverageWitness is retained: site activity is not observable, and a \
                        missing event is not absence."
                .to_owned(),
            knowledge_state: KnowledgeState::NotObservable,
            provenance: ProvenanceClass::Derived,
            hypothesis: None,
            evidence: Vec::new(),
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        })?,
    ];
    let mut nominal = BTreeSet::from([
        CLAIM_LEDGER_HEAD.to_owned(),
        CLAIM_IMPORTS.to_owned(),
        CLAIM_EFFECT_JOURNAL.to_owned(),
    ]);

    let corroborated = planned
        .iter()
        .filter(|event| event.retained.corroborated())
        .count();
    let tampered = planned
        .iter()
        .filter(|event| event.retained.tamper.has_open_tamper())
        .count();
    if let Some(top) = headline {
        nominal.insert(CLAIM_EVENTS.to_owned());
        cells.push(known_cell(
            CLAIM_EVENTS,
            format!(
                "{}: {}; {corroborated} corroborated; {tampered} with open sensor tamper; highest \
                 consequence: {}.",
                plural(planned.len(), "published event", "published events"),
                state_counts(&planned),
                top.id()
            ),
            vec![ledger_evidence],
        )?);
    }

    // Worlds: one aggregate per world kind across every published event, keeping the maximum
    // severity and protection of its members; the per-event worlds hydrate through the handles.
    let (world_classes, memberships) = aggregate_worlds(&planned);
    let aggregated_world_count: usize = world_classes
        .values()
        .map(|class| class.members.len())
        .sum();
    let mut alternatives = Vec::new();
    let mut residuals = vec![PossibleWorld {
        world_id: WORLD_UNOBSERVED_ACTIVITY.to_owned(),
        description: "Activity outside retained evidence remains possible.".to_owned(),
        claim_ids: BTreeSet::from([CLAIM_COVERAGE.to_owned()]),
        evidence: vec![anchor.state_root],
        consequence_severity: 4,
        protected: true,
    }];
    for (class_id, class) in &world_classes {
        let world = PossibleWorld {
            world_id: class_id.clone(),
            description: format!(
                "{} of {}: {}",
                class.members.len(),
                plural(planned.len(), "event", "events"),
                class.description
            ),
            claim_ids: BTreeSet::from([CLAIM_EVENTS.to_owned()]),
            evidence: vec![ledger_evidence],
            consequence_severity: class.severity,
            protected: class.protected,
        };
        if class.residual {
            residuals.push(world);
        } else {
            alternatives.push(world);
        }
    }

    if heartbeat && !planned.is_empty() {
        // The heartbeat folds every protected world into one summary world; the per-kind worlds
        // are inline in brief, and every per-event world hydrates through its event's handle.
        let severity = alternatives
            .iter()
            .chain(&residuals)
            .filter(|world| world.protected)
            .map(|world| world.consequence_severity)
            .max()
            .unwrap_or(0);
        let folded = alternatives
            .iter()
            .chain(&residuals)
            .filter(|world| world.protected)
            .count();
        residuals = vec![PossibleWorld {
            world_id: WORLD_PROTECTED_SUMMARY.to_owned(),
            description: format!(
                "{folded} protected world kinds (max severity {severity}): unobserved activity, \
                 {aggregated_world_count} event worlds."
            ),
            claim_ids: BTreeSet::from([CLAIM_COVERAGE.to_owned(), CLAIM_EVENTS.to_owned()]),
            evidence: vec![ledger_evidence],
            consequence_severity: severity,
            protected: true,
        }];
        alternatives = Vec::new();
    }

    // Aggregated epistemic boundaries: one statement per physical knowledge state.
    let mut by_state: BTreeMap<&str, usize> = BTreeMap::new();
    for event in &planned {
        if event.section.physical_state != KnowledgeState::Known {
            *by_state
                .entry(event.section.physical_state.as_str())
                .or_default() += 1;
        }
    }
    for (state, count) in by_state.iter().filter(|_| !heartbeat) {
        unknown.push(format!(
            "Whether {} real activity is {state}.",
            plural(
                *count,
                "published event reflects",
                "published events reflect"
            )
        ));
    }
    let rejected = planned
        .iter()
        .filter(|event| event.retained.event.state == EventState::Rejected)
        .count();
    if rejected > 0 {
        unknown.push(format!(
            "{} not a certified negative read.",
            plural(rejected, "rejection is", "rejections are")
        ));
    }
    let uncorroborated = planned.len() - corroborated;
    if uncorroborated > 0 {
        warnings.push(format!(
            "{} single-sensor and not corroborated; none grants alert or effect authority.",
            plural(uncorroborated, "published event is", "published events are")
        ));
    }

    let mut coverage_handles = BTreeSet::from([format!("{deployment_handle}/coverage")]);
    let mut inline_ids = Vec::new();
    let mut contradictions = Vec::new();
    let mut epistemic_state = KnowledgeState::NotObservable;
    for event in &planned {
        if severity_rank(event.section.physical_state) > severity_rank(epistemic_state) {
            epistemic_state = event.section.physical_state;
        }
        contradictions.extend(
            event
                .section
                .cells
                .iter()
                .filter(|cell| {
                    !cell.contradictions().is_empty()
                        || cell.knowledge_state() == KnowledgeState::Conflicted
                })
                .map(|cell| cell.claim_id().to_owned()),
        );
        // Every event's committed roots stay proof pointers; per-edge evidence joins only for
        // inline events (the rest hydrates through the event's handle).
        proof_roots.insert(event.retained.event_root);
        proof_roots.insert(event.retained.revision_digest);
        if !event.inline {
            continue;
        }
        inline_ids.push(event.id().to_owned());
        nominal.insert(event.section.lifecycle_claim.clone());
        cells.extend(event.section.cells.iter().cloned());
        proof_roots.extend(event.section.proof_roots.iter().copied());
        if event.section.contradicted || event.retained.tamper.has_open_tamper() {
            unknown.extend(event.section.unknown.iter().cloned());
            at_risk.extend(event.section.at_risk.iter().cloned());
        }
        coverage_handles.insert(format!("fss://event/{}/coverage", event.id()));
    }
    contradictions.sort();
    contradictions.dedup();

    let open_obligations = snapshot.open_obligations();
    let indeterminate = snapshot.indeterminate_operations();
    for obligation in &open_obligations {
        at_risk.push(format!(
            "Obligation {} for operation {} is {}.",
            obligation.obligation_id,
            obligation.operation_id,
            obligation_state_str(obligation.state)
        ));
    }
    for operation in &indeterminate {
        at_risk.push(format!(
            "Operation {} may have occurred; reconcile before any resend.",
            operation.intent.operation_id
        ));
    }
    if snapshot.doctor_verdict == DoctorVerdict::AttentionRequired {
        at_risk.push("fss doctor: attention_required.".to_owned());
        degradation.push(
            "The deployment doctor reports attention_required; only the committed prefix was read."
                .to_owned(),
        );
    }
    if snapshot.ledger_tail_uncommitted || snapshot.effect_tail_uncommitted {
        at_risk.push("A journal ends with bytes beyond its committed prefix.".to_owned());
    }

    // Affordances: listed with class, capability, and cost; never executed by orient.
    let all_worlds: BTreeSet<String> = alternatives
        .iter()
        .chain(&residuals)
        .map(|world| world.world_id.clone())
        .collect();
    let deployment_read = read_cost(snapshot.bytes_read, snapshot.files_read)?;
    let mut affordances = vec![
        ListedAffordance {
            affordance_id: AFFORDANCE_REORIENT.to_owned(),
            operation: "session.orient",
            target: deployment_handle.clone(),
            rationale: format!("Re-orient after commit {}.", anchor.commit_sequence),
            class: AffordanceClass::Wait,
            supported_worlds: all_worlds,
            required_capability: CAPABILITY_SITUATION_READ,
            cost: deployment_read,
        }
        .build(),
    ];
    if heartbeat {
        degradation.push(
            "The pulse view lists only the re-orient heartbeat affordance; `--view brief` lists \
             the complete affordance frontier."
                .to_owned(),
        );
    } else {
        for (rank, event) in planned.iter().enumerate() {
            if !event.inline && rank > 0 {
                continue;
            }
            affordances.push(explain_affordance(
                event.retained,
                memberships.get(event.id()).cloned().unwrap_or_default(),
                deployment_read,
            ));
        }
        affordances.push(
            ListedAffordance {
                affordance_id: AFFORDANCE_DOCTOR.to_owned(),
                operation: "doctor",
                target: format!("{deployment_handle}/doctor"),
                rationale: "Diagnose the root read-only (`fss doctor`).".to_owned(),
                class: AffordanceClass::Probe,
                supported_worlds: BTreeSet::new(),
                required_capability: CAPABILITY_DOCTOR,
                cost: deployment_read,
            }
            .build(),
        );
        affordances.push(
            ListedAffordance {
                affordance_id: AFFORDANCE_FOLLOW.to_owned(),
                operation: "session.follow",
                target: deployment_handle.clone(),
                rationale: "Not exposed by this build.".to_owned(),
                class: AffordanceClass::Unavailable,
                supported_worlds: BTreeSet::new(),
                required_capability: CAPABILITY_SITUATION_READ,
                cost: read_cost(0, 0)?,
            }
            .build(),
        );
        affordances.push(
            ListedAffordance {
                affordance_id: AFFORDANCE_PLAN.to_owned(),
                operation: "plan",
                target: deployment_handle.clone(),
                rationale: "Not exposed; no policy grants effect authority.".to_owned(),
                class: AffordanceClass::Unavailable,
                supported_worlds: BTreeSet::new(),
                required_capability: CAPABILITY_PLAN_PREPARE,
                cost: read_cost(0, 0)?,
            }
            .build(),
        );
    }
    for operation in &indeterminate {
        affordances.push(
            ListedAffordance {
                affordance_id: format!(
                    "{AFFORDANCE_RECONCILE_PREFIX}{}",
                    operation.intent.operation_id
                ),
                operation: "commit",
                target: format!("fss://operation/{}", operation.intent.operation_id),
                rationale:
                    "Reconciliation is not exposed by this build; no resend is safe before lookup."
                        .to_owned(),
                class: AffordanceClass::Blocked,
                supported_worlds: BTreeSet::new(),
                required_capability: CAPABILITY_PLAN_COMMIT,
                cost: read_cost(0, 0)?,
            }
            .build(),
        );
    }
    affordances.sort_by(|left, right| left.affordance_id.cmp(&right.affordance_id));
    let next: Vec<String> = affordances
        .iter()
        .filter(|candidate| {
            !matches!(
                candidate.class,
                AffordanceClass::Blocked | AffordanceClass::Unavailable
            )
        })
        .map(|candidate| candidate.affordance_id.clone())
        .collect();

    let mut obligation_ids: Vec<ObligationId> = open_obligations
        .iter()
        .map(|obligation| obligation.obligation_id.clone())
        .collect();
    obligation_ids.sort();
    obligation_ids.dedup();

    let now = vec![match headline {
        Some(top) => format!(
            "Commit {}: {} ({}), {corroborated} corroborated, {} open; top: {}.",
            anchor.commit_sequence,
            plural(planned.len(), "event", "events"),
            state_counts(&planned),
            plural(obligation_ids.len(), "obligation", "obligations"),
            top.id()
        ),
        None => format!(
            "Commit {}: 0 events, {}, {} open.",
            anchor.commit_sequence,
            plural(snapshot.completed_imports.len(), "import", "imports"),
            plural(obligation_ids.len(), "obligation", "obligations"),
        ),
    }];
    why.push(format!(
        "Compiled read-only from the committed ledger prefix (root {}) and effect journal.",
        snapshot.ledger_root
    ));

    let envelope_identity = digest_of("fss.reference_orient_worlds.v2", |encoder| {
        encoder.text(&objective_id);
        anchor.encode_canonical(encoder);
        encoder.u64(alternatives.len() as u64);
        for world in alternatives.iter().chain(&residuals) {
            world.encode_canonical(encoder);
        }
    });
    let world_envelope = WorldEnvelope {
        envelope_id: format!("worlds:{}", short_identity(envelope_identity)),
        objective_id: objective_id.clone(),
        anchor: anchor.clone(),
        certified_core_claim_ids: nominal.clone(),
        nominal_claim_ids: nominal,
        alternatives,
        adversarial_residuals: residuals,
        common_invariants: BTreeSet::from([
            "invariant:evidence-provenance-retained".to_owned(),
            "invariant:no-alert-authority-from-model-output-alone".to_owned(),
            "invariant:orient-is-read-only".to_owned(),
        ]),
        coverage_boundary_handles: coverage_handles,
    };
    let evidence_handles = proof_roots
        .iter()
        .map(|digest| format!("fss://proof/{digest}"))
        .collect();
    let identity = digest_of("fss.reference_orient_capsule.v2", |encoder| {
        encoder.digest(basis.basis_digest());
        encoder.text(request.view.id());
        encoder.text(&objective_id);
        request.principal.encode_canonical(encoder);
        anchor.encode_canonical(encoder);
        encoder.digest(envelope_identity);
        for cell in &cells {
            encoder.digest(cell.cell_digest());
        }
        for affordance in &affordances {
            affordance.encode_canonical(encoder);
        }
        for obligation in &obligation_ids {
            obligation.encode_canonical(encoder);
        }
    });
    let frame = SituationFrame {
        frame_id: format!("frame:{}", short_identity(identity)),
        objective_id,
        anchor: anchor.clone(),
        world_envelope,
        knowledge_cells: cells,
        now,
        changed: Vec::new(),
        why,
        unknown,
        at_risk,
        next,
        evidence_handles,
    };
    let capsule = SituationCapsule {
        capsule_id: format!("situation:{identity}"),
        revision: anchor.commit_sequence,
        contract_basis: basis,
        mission_id,
        session_id,
        principal_id: request.principal.clone(),
        anchor,
        previous_anchor: None,
        frame,
        obligations: obligation_ids,
        affordances,
        completeness: Completeness::Partial,
        created_at: snapshot.latest_evidence_time,
        mission_state: None,
    };
    capsule.validate()?;
    for cell in &capsule.frame.knowledge_cells {
        if severity_rank(cell.knowledge_state()) > severity_rank(epistemic_state) {
            epistemic_state = cell.knowledge_state();
        }
    }

    let hydration = event_hydration(snapshot, &planned)?;
    let folded_worlds = if heartbeat && !planned.is_empty() {
        let cost = BudgetVector::builder()
            .tokens(u64::from(AgentView::Brief.maximum_tokens()))
            .bytes(snapshot.bytes_read)
            .storage_operations(snapshot.files_read)
            .build()
            .map_err(|_| ContractError::BudgetExhausted)?;
        Some(ExpansionHandle {
            handle: format!("{deployment_handle}/worlds"),
            purpose: format!(
                "Per-kind protected worlds ({WORLD_UNOBSERVED_ACTIVITY} and {WORLD_EVENTS_PREFIX}*) \
                 via `fss orient --view brief`."
            ),
            estimated_cost: cost,
        })
    } else {
        None
    };
    let source = source_omissions(
        &planned,
        &hydration,
        aggregated_world_count,
        world_classes.len(),
        folded_worlds,
    );
    let candidate_world_count = aggregated_world_count + 1;
    let attention = attention_frontier(snapshot, &planned, &deployment_handle);
    let epistemic_debt = epistemic_debt(snapshot, &planned);
    Ok(CompiledSituation {
        capsule,
        proof_roots,
        degradation,
        warnings,
        source,
        hydration,
        headline_event: headline.map(|top| top.retained.event.event_id.clone()),
        candidate_world_count,
        aggregated_world_count,
        epistemic_state,
        contradictions,
        attention,
        epistemic_debt,
    })
}

/// Listed (never executed) explanation of one event.
fn explain_affordance(
    retained: &RetainedEvent,
    supported_worlds: BTreeSet<String>,
    cost: BudgetVector,
) -> ActionAffordance {
    let event = retained.event.event_id.as_str();
    ListedAffordance {
        affordance_id: format!("{AFFORDANCE_EXPLAIN_PREFIX}{event}"),
        operation: "explain",
        target: format!("fss://event/{event}"),
        rationale: "Explain this event (`fss explain`).".to_owned(),
        class: AffordanceClass::Probe,
        supported_worlds,
        required_capability: CAPABILITY_EXPLAIN,
        cost,
    }
    .build()
}

/// The hydration slot of every published event, in consequence-rank order.
fn event_hydration(
    snapshot: &DeploymentSnapshot,
    planned: &[PlannedEvent<'_>],
) -> Result<Vec<EventHydration>, ContractError> {
    let synopsis_cost = BudgetVector::builder()
        .tokens(u64::from(AgentView::DecisionDiff.maximum_tokens()))
        .bytes(snapshot.bytes_read)
        .storage_operations(snapshot.files_read)
        .build()
        .map_err(|_| ContractError::BudgetExhausted)?;
    planned
        .iter()
        .map(|event| {
            let retained = event.retained;
            Ok(EventHydration {
                event_id: retained.event.event_id.clone(),
                handle: format!(
                    "fss://event/{}/revision/{}",
                    event.id(),
                    retained.event.revision
                ),
                revision_digest: retained.revision_digest,
                world_ids: event
                    .section
                    .worlds()
                    .map(|world| world.world_id.clone())
                    .collect(),
                protected_world_ids: event
                    .section
                    .worlds()
                    .filter(|world| world.protected)
                    .map(|world| world.world_id.clone())
                    .collect(),
                cells_inline: event.inline,
                cell_count: event.section.cells.len(),
                physical_state: event.section.physical_state,
                consequence_severity: event.section.protected_severity(),
                summary: format!(
                    "Revision {} in state {}; physical presence {}; {}.",
                    retained.event.revision,
                    retained.event.state.as_str(),
                    event.section.physical_state.as_str(),
                    if retained.corroborated() {
                        "corroborated"
                    } else {
                        "not corroborated"
                    }
                ),
                synopsis_cost,
                source_cost: read_cost(retained.object_bytes, retained.object_reads)?,
            })
        })
        .collect()
}

/// What this view compiled out at the source, and the priced handle of every event.
fn source_omissions(
    planned: &[PlannedEvent<'_>],
    hydration: &[EventHydration],
    aggregated_worlds: usize,
    world_classes: usize,
    folded_worlds: Option<ExpansionHandle>,
) -> SourceOmissions {
    if planned.is_empty() {
        return SourceOmissions::default();
    }
    let mut omissions = Vec::new();
    let summarized = planned.iter().filter(|event| !event.inline).count();
    if summarized > 0 {
        omissions.push(SourceOmission {
            class: SOURCE_CLASS_EVENT_DETAIL.to_owned(),
            omitted_count: summarized as u64,
            transform: CompressionTransform {
                kind: CompressionTransformKind::Summarize,
                scope: "published events".to_owned(),
                loss_class: CompressionLossClass::DecisionPreserving,
                details: Some(format!(
                    "{summarized} of {} events are summarized by {CLAIM_EVENTS} and the \
                     per-state epistemic boundaries; each event's cells hydrate through its \
                     handle.",
                    planned.len()
                )),
            },
        });
    }
    let folded = folded_worlds.is_some();
    omissions.push(SourceOmission {
        class: SOURCE_CLASS_WORLD_DETAIL.to_owned(),
        // Folding also represents the deployment's unobserved-activity world.
        omitted_count: aggregated_worlds as u64 + u64::from(folded),
        transform: CompressionTransform {
            kind: CompressionTransformKind::Aggregate,
            scope: "per-event possible worlds".to_owned(),
            loss_class: CompressionLossClass::DecisionPreserving,
            details: Some(if folded {
                format!(
                    "{aggregated_worlds} per-event worlds and {WORLD_UNOBSERVED_ACTIVITY} are \
                     folded into {WORLD_PROTECTED_SUMMARY}, keeping the maximum severity and \
                     protection; every member hydrates through its handle."
                )
            } else {
                format!(
                    "{aggregated_worlds} per-event worlds are aggregated into {world_classes} \
                     class worlds keeping each class's maximum severity and protection; every \
                     member hydrates through its event's handle."
                )
            }),
        },
    });
    let mut handles: Vec<ExpansionHandle> = hydration
        .iter()
        .map(|slot| ExpansionHandle {
            handle: slot.handle.clone(),
            purpose: format!(
                "H1 synopsis of {} (`fss explain --event-id {}`): knowledge cells and worlds {}.",
                slot.event_id.as_str(),
                slot.event_id.as_str(),
                slot.world_ids.join(", ")
            ),
            estimated_cost: slot.synopsis_cost,
        })
        .collect();
    handles.extend(folded_worlds);
    SourceOmissions { omissions, handles }
}

/// Ranked attention frontier: open obligations and indeterminate effects, the coverage gap, and
/// the highest-consequence unresolved event.
fn attention_frontier(
    snapshot: &DeploymentSnapshot,
    planned: &[PlannedEvent<'_>],
    deployment_handle: &str,
) -> Vec<AttentionItem> {
    let mut items = Vec::new();
    for operation in snapshot.indeterminate_operations() {
        let id = operation.intent.operation_id.as_str();
        items.push(AttentionItem {
            item_id: format!("attention:effect:{id}"),
            kind: "indeterminate_effect",
            priority_class: "critical",
            mission_relevance: 1.0,
            decision_impact: 5.0,
            reason: format!("Operation {id} may have occurred; reconcile before any resend."),
            handle: format!("fss://operation/{id}"),
        });
    }
    for obligation in snapshot.open_obligations() {
        let id = obligation.obligation_id.as_str();
        items.push(AttentionItem {
            item_id: format!("attention:obligation:{id}"),
            kind: "obligation",
            priority_class: "critical",
            mission_relevance: 1.0,
            decision_impact: 5.0,
            reason: format!(
                "Obligation {id} is {}.",
                obligation_state_str(obligation.state)
            ),
            handle: format!("fss://obligation/{id}"),
        });
    }
    if let Some(top) = planned.first() {
        let severity = top.section.protected_severity();
        items.push(AttentionItem {
            item_id: format!("attention:event:{}", top.id()),
            kind: "event",
            priority_class: if top.retained.tamper.has_open_tamper() {
                "critical"
            } else if severity >= 4 {
                "high"
            } else {
                "normal"
            },
            mission_relevance: 1.0,
            decision_impact: f64::from(severity),
            reason: format!(
                "Highest-consequence published event: state {}, physical presence {}, {}.",
                top.retained.event.state.as_str(),
                top.section.physical_state.as_str(),
                if top.retained.corroborated() {
                    "corroborated"
                } else {
                    "not corroborated"
                }
            ),
            handle: format!("fss://event/{}", top.id()),
        });
    }
    items.push(AttentionItem {
        item_id: "attention:coverage:site".to_owned(),
        kind: "coverage_gap",
        priority_class: "high",
        mission_relevance: 1.0,
        decision_impact: 4.0,
        reason: "No CoverageWitness is retained; absence cannot be certified.".to_owned(),
        handle: format!("{deployment_handle}/coverage"),
    });
    // The schema bounds the frontier; everything past the head stays in obligations and
    // indeterminateEffects, which are never truncated.
    items.truncate(128);
    items
}

/// Assumptions this orientation rests on.
fn epistemic_debt(
    snapshot: &DeploymentSnapshot,
    planned: &[PlannedEvent<'_>],
) -> Vec<EpistemicDebtItem> {
    let mut debt = vec![EpistemicDebtItem {
        debt_id: "debt:coverage:uncertified".to_owned(),
        assumption: "Absence is never inferred: every interval without a CoverageWitness is \
                     treated as unobserved."
            .to_owned(),
        deferred_reason: "No producer in this deployment retains CoverageWitness records."
            .to_owned(),
        dependent_decisions: vec!["any absence or all-clear conclusion".to_owned()],
        consequence_if_wrong: "Treating unobserved time as clear would hide real activity."
            .to_owned(),
        cheapest_test: "Retain a continuous CoverageWitness over the zone and re-orient."
            .to_owned(),
        review_trigger: "A coverage witness is committed to the ledger.".to_owned(),
    }];
    let uncorroborated = planned
        .iter()
        .filter(|event| !event.retained.corroborated())
        .count();
    if uncorroborated > 0 {
        debt.push(EpistemicDebtItem {
            debt_id: "debt:events:failure-domain-independence".to_owned(),
            assumption: "Failure domains are independent only when their names differ.".to_owned(),
            deferred_reason: "No shared-failure-domain registry is retained.".to_owned(),
            dependent_decisions: vec![format!(
                "corroboration of {}",
                plural(uncorroborated, "published event", "published events")
            )],
            consequence_if_wrong:
                "Two sources sharing an unnamed failure could be miscounted as corroboration."
                    .to_owned(),
            cheapest_test: "Register each contributing sensor's failure domains.".to_owned(),
            review_trigger: "Supporting evidence from a second failure domain is committed."
                .to_owned(),
        });
    }
    if snapshot.ledger_tail_uncommitted || snapshot.effect_tail_uncommitted {
        debt.push(EpistemicDebtItem {
            debt_id: "debt:journal:uncommitted-tail".to_owned(),
            assumption: "Only the committed journal prefix is authority; tail bytes are ignored."
                .to_owned(),
            deferred_reason: "orient is read-only and never repairs a journal.".to_owned(),
            dependent_decisions: vec!["every conclusion of this orientation".to_owned()],
            consequence_if_wrong: "A torn tail could hide a committed record.".to_owned(),
            cheapest_test: "Run `fss doctor --json --root <dir>`.".to_owned(),
            review_trigger: "The doctor verdict changes.".to_owned(),
        });
    }
    debt
}

/// One listed (never executed) affordance of the orientation frontier.
struct ListedAffordance<'a> {
    affordance_id: String,
    operation: &'a str,
    target: String,
    rationale: String,
    class: AffordanceClass,
    supported_worlds: BTreeSet<String>,
    required_capability: &'a str,
    cost: BudgetVector,
}

impl ListedAffordance<'_> {
    fn build(self) -> ActionAffordance {
        ActionAffordance {
            affordance_id: self.affordance_id,
            operation: self.operation.to_owned(),
            target: self.target,
            rationale: self.rationale,
            class: self.class,
            supported_worlds: self.supported_worlds,
            unsafe_worlds: BTreeSet::new(),
            required_capabilities: BTreeSet::from([self.required_capability.to_owned()]),
            cost: self.cost,
            reversible: true,
            branch_predicate: None,
        }
    }
}

/// The read-only objective every orientation answers.
fn orientation_objective(
    snapshot: &DeploymentSnapshot,
    request: &OrientRequest,
    capsule: &SituationCapsule,
    request_digest: ContentDigest,
    requested: BudgetVector,
) -> Result<ObjectiveContract, ContractError> {
    let anchor = &capsule.anchor;
    let mut zones: Vec<String> = snapshot
        .events
        .iter()
        .flat_map(|retained| retained.event.zone_ids.iter().cloned())
        .collect();
    zones.sort();
    zones.dedup();
    let decision = digest_of("fss.reference_orient_objective.v1", |encoder| {
        encoder.digest(request_digest);
        anchor.encode_canonical(encoder);
        encoder.text(request.view.id());
    });
    ObjectiveContract::new(ObjectiveContractParams {
        objective_id: capsule.frame.objective_id.clone(),
        source_principal: request.principal.as_str().to_owned(),
        source_request_digest: request_digest.to_text(),
        desired_outcome: format!(
            "A read-only {} orientation of deployment {} pinned to commit {}.",
            request.view.name(),
            snapshot.site_lineage,
            anchor.commit_sequence
        ),
        success_predicates: vec![
            "Every protected world is inline or hydratable through a receipted handle.".to_owned(),
            "The context pack is admitted within the view's registered token budget.".to_owned(),
        ],
        failure_predicates: vec![
            "The critical context does not fit the admitted budget \
             (ERR-AGENT-CONTEXT-INCOMPLETE-001)."
                .to_owned(),
        ],
        stop_conditions: vec!["The committed ledger prefix has been read once.".to_owned()],
        hard_constraints: vec![
            "Read-only: nothing under the root is created, written, locked, or repaired."
                .to_owned(),
            "No listed affordance is executed.".to_owned(),
        ],
        soft_preferences: Vec::new(),
        scope: ObjectiveScope {
            deployments: vec![snapshot.site_lineage.clone()],
            zones,
            subjects: Vec::new(),
            devices: Vec::new(),
            time_intervals: Vec::new(),
            data_classes: ORIENT_DATA_CLASSES
                .iter()
                .map(|&class| class.to_owned())
                .collect(),
        },
        budgets: requested,
        allowed_actions: vec!["session.orient".to_owned()],
        required_approvals: Vec::new(),
        terminal_proof: vec![format!("fss://proof/{}", snapshot.ledger_root)],
        decision_digest: decision.to_text(),
    })
}

/// Data classes an orientation reads (every other class is outside its projection).
pub const ORIENT_DATA_CLASSES: [&str; 4] = [
    "authority-ledger",
    "effect-journal",
    "event-revisions",
    "deployment-layout",
];

fn orientation_validity(snapshot: &DeploymentSnapshot) -> OrientValidity {
    OrientValidity {
        valid_until: snapshot.latest_evidence_time,
        invalidators: vec![
            format!(
                "The authority ledger commits past sequence {}.",
                snapshot.anchor.commit_sequence
            ),
            format!(
                "The durable effect journal changes from {}.",
                snapshot.effect_journal_digest
            ),
            "A schema, policy, privacy, or adapter-registry epoch changes.".to_owned(),
        ],
        reanchor_required_on: vec![
            "ledger_head_advance".to_owned(),
            "effect_journal_change".to_owned(),
            "epoch_change".to_owned(),
        ],
    }
}

/// Section entry budget of the AOP-003 projection for one view.
fn orient_budget(view: AgentView) -> Result<OrientBudget, ContractError> {
    let tokens = view.target_tokens();
    OrientBudget::new((tokens / 30).max(4), (tokens / 10).max(8))
}

fn projection_spec(
    view: AgentView,
    tokens: u64,
    degraded: bool,
) -> Result<ReferenceProjectionSpec, ContractError> {
    let available = BudgetVector::builder()
        .tokens(tokens)
        .bytes(4 * 1024 * 1024)
        .build()
        .map_err(|_| ContractError::BudgetExhausted)?;
    Ok(ReferenceProjectionSpec {
        view_id: view.id().to_owned(),
        available_resources: available,
        reserved_resources: BudgetVector::ZERO,
        pressure: if degraded {
            ResourcePressure::Elevated
        } else {
            ResourcePressure::Nominal
        },
        degraded_dimensions: if degraded {
            BTreeSet::from(["tokens".to_owned()])
        } else {
            BTreeSet::new()
        },
        target_tokens: tokens,
    })
}

fn is_budget_refusal(error: &ReferenceError) -> bool {
    matches!(
        error,
        ReferenceError::Contract(ContractError::BudgetExhausted)
    )
}

/// Compiles one read-only orientation of `snapshot` for `request`.
///
/// Supported views are `pulse`, `brief`, and `epistemic_map`. Every published event is ranked by
/// consequence; the view carries the per-event cells of its top-ranked events (and of every event
/// with contradicting evidence or open tamper) inline, summarizes the rest, and aggregates every
/// per-event world into one world per kind that keeps the kind's maximum severity and protection.
/// Each event keeps a priced hydration handle in the compression receipt. The critical context
/// (protected worlds, epistemic boundaries, risks, obligations, next and blocked affordances) is
/// never truncated: if it does not fit the admitted budget the orientation is refused with
/// [`OrientError::ContextBudgetExceeded`].
pub fn orient_deployment(
    snapshot: &DeploymentSnapshot,
    request: &OrientRequest,
    limits: &OrientLimits,
) -> Result<DeploymentOrientation, OrientError> {
    if !matches!(
        request.view,
        AgentView::Pulse | AgentView::Brief | AgentView::EpistemicMap
    ) {
        return Err(OrientError::UnsupportedView(request.view));
    }
    if snapshot.events.len() > limits.max_events {
        return Err(OrientError::TooManyEvents {
            published: snapshot.events.len(),
            maximum: limits.max_events,
        });
    }
    let compiled = compile_capsule(snapshot, request)?;
    let mut degradation = compiled.degradation;
    let situation = ReferenceSituation::new(compiled.capsule, compiled.proof_roots);
    let target = u64::from(request.view.target_tokens());
    let maximum = u64::from(request.view.maximum_tokens());
    let project = |situation: ReferenceSituation, tokens: u64, degraded: bool| {
        project_reference_situation_with_source_omissions(
            situation,
            &projection_spec(request.view, tokens, degraded)?,
            &compiled.source,
        )
    };
    let (publication, target_tokens) = match request.budget_tokens {
        Some(tokens) => match project(situation, tokens, false) {
            Ok(publication) => (publication, tokens),
            Err(error) if is_budget_refusal(&error) => {
                return Err(OrientError::ContextBudgetExceeded {
                    view: request.view,
                    budget_tokens: tokens,
                });
            }
            Err(error) => return Err(error.into()),
        },
        None => match project(situation.clone(), target, false) {
            Ok(publication) => (publication, target),
            Err(error) if is_budget_refusal(&error) => match project(situation, maximum, true) {
                Ok(publication) => {
                    degradation.push(format!(
                        "The critical context exceeds the {} target of {target} tokens; it \
                         was admitted at the registered maximum of {maximum} tokens.",
                        request.view.name()
                    ));
                    (publication, maximum)
                }
                Err(error) if is_budget_refusal(&error) => {
                    return Err(OrientError::ContextBudgetExceeded {
                        view: request.view,
                        budget_tokens: maximum,
                    });
                }
                Err(error) => return Err(error.into()),
            },
            Err(error) => return Err(error.into()),
        },
    };
    let capsule = &publication.situation.capsule;
    let projection = orient_projection(capsule, orient_budget(request.view)?)?;
    let requested = BudgetVector::builder()
        .tokens(target_tokens)
        .build()
        .map_err(|_| ContractError::BudgetExhausted)?;
    let consumed = BudgetVector::builder()
        .tokens(publication.context_pack.token_count)
        .bytes(snapshot.bytes_read)
        .storage_operations(snapshot.files_read)
        .build()
        .map_err(|_| ContractError::BudgetExhausted)?;
    degradation.push(
        "Latency and CPU time are not metered by this reference path; consumed reports reads and \
         context tokens only."
            .to_owned(),
    );
    let summarized = compiled
        .hydration
        .iter()
        .filter(|slot| !slot.cells_inline)
        .count();
    if !compiled.hydration.is_empty() {
        degradation.push(format!(
            "{} per-event worlds are aggregated into class worlds and {summarized} of {} events \
             are summarized; each event hydrates through its receipted handle.",
            compiled.aggregated_world_count,
            compiled.hydration.len()
        ));
    }
    let open_obligations = capsule.obligations.clone();
    let mut indeterminate_effects: Vec<OperationId> = snapshot
        .indeterminate_operations()
        .iter()
        .map(|operation| operation.intent.operation_id.clone())
        .collect();
    indeterminate_effects.sort();
    let request_digest = request.digest_at(&snapshot.anchor);
    let objective = orientation_objective(snapshot, request, capsule, request_digest, requested)?;
    Ok(DeploymentOrientation {
        view: request.view,
        projection,
        target_tokens,
        open_obligations,
        indeterminate_effects,
        degradation,
        warnings: compiled.warnings,
        contradictions: compiled.contradictions,
        epistemic_state: compiled.epistemic_state,
        requested,
        consumed,
        request_digest,
        objective,
        attention: compiled.attention,
        epistemic_debt: compiled.epistemic_debt,
        validity: orientation_validity(snapshot),
        hydration: compiled.hydration,
        headline_event: compiled.headline_event,
        candidate_world_count: compiled.candidate_world_count,
        aggregated_world_count: compiled.aggregated_world_count,
        privacy_generation_id: format!("privacy-epoch:{}", snapshot.anchor.privacy_epoch),
        publication,
    })
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
    pub affordances: Vec<ActionAffordance>,
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

/// Explains one published event against a compiled orientation of the same snapshot.
///
/// The event's cells and worlds are compiled from its committed revision directly, so every
/// published event is explainable whether or not the orientation carried it inline. Returns
/// `Ok(None)` when no committed `event_revision` delta names `event_id`.
pub fn explain_event(
    snapshot: &DeploymentSnapshot,
    orientation: &DeploymentOrientation,
    event_id: &EventId,
) -> Result<Option<EventExplanation>, OrientError> {
    let Some(retained) = snapshot.event(event_id) else {
        return Ok(None);
    };
    let Some(hydration) = orientation
        .hydration
        .iter()
        .find(|slot| slot.event_id == *event_id)
        .cloned()
    else {
        return Ok(None);
    };
    let section = event_section(retained)?;
    let capsule = orientation.capsule();
    let worlds: Vec<PossibleWorld> = section.worlds().cloned().collect();
    let residual_ids = section
        .residuals
        .iter()
        .map(|world| world.world_id.clone())
        .collect();
    let explain_cost = read_cost(snapshot.bytes_read, snapshot.files_read)?;
    let mut affordances = vec![explain_affordance(
        retained,
        worlds.iter().map(|world| world.world_id.clone()).collect(),
        explain_cost,
    )];
    affordances.extend(
        capsule
            .affordances
            .iter()
            .filter(|candidate| candidate.affordance_id == AFFORDANCE_REORIENT)
            .cloned(),
    );
    affordances.sort_by(|left, right| left.affordance_id.cmp(&right.affordance_id));
    let next_actions: Vec<String> = affordances
        .iter()
        .map(|candidate| candidate.affordance_id.clone())
        .collect();

    let event = &retained.event;
    let domains = retained.failure_domains();
    let mut would_change = Vec::new();
    if !retained.corroborated() {
        would_change.push(format!(
            "Supporting evidence from a failure domain other than [{}] would allow corroboration.",
            domains.iter().cloned().collect::<Vec<_>>().join(",")
        ));
    }
    would_change.push(
        "A contradicting evidence edge in a new revision would make the presence claim conflicted."
            .to_owned(),
    );
    would_change.push(
        "A complete continuous CoverageWitness over the zone would be required before absence \
         could be certified."
            .to_owned(),
    );
    if event.state == EventState::Indeterminate {
        would_change.push(
            "A policy revision adjudicating the candidate would replace the indeterminate state."
                .to_owned(),
        );
    }
    if retained.tamper.has_open_tamper() {
        would_change.push(
            "Evidenced integrity restoration would retire the open sensor-tamper report."
                .to_owned(),
        );
    }
    let assumptions = vec![
        format!(
            "Revision {} is the latest committed revision at commit {}.",
            event.revision, capsule.anchor.commit_sequence
        ),
        "Failure domains are independent only when their names differ.".to_owned(),
    ];
    let mut subgraph = vec![retained.event_root, retained.revision_digest];
    subgraph.extend(event.evidence.iter().map(|edge| edge.digest));
    subgraph.extend(event.model_receipts.iter().copied());
    let handles = vec![
        hydration.handle.clone(),
        format!("fss://event/{}/coverage", event_id.as_str()),
    ];
    let receipt = ExplainReceipt::compile(
        ExplainQuestion::Why,
        retained.revision_digest,
        subgraph,
        handles,
        16,
    )?;
    Ok(Some(EventExplanation {
        event: retained.clone(),
        receipt,
        cells: section.cells,
        worlds,
        residual_ids,
        affordances,
        next_actions,
        would_change,
        assumptions,
        warnings: section.warnings,
        hydration,
    }))
}

#[cfg(test)]
mod tests;
