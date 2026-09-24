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
//! Every output is a pure function of the committed bytes: the capsule time is the latest
//! committed evidence time, not the wall clock, so the same root yields identical output.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;

use fss_core::{
    ActionAffordance, AffordanceClass, AgentView, BudgetVector, CanonicalDecode, CanonicalEncode,
    CanonicalEncoder, Completeness, ContentDigest, ContractError, EffectState, EventHypothesis,
    EventId, EventState, ExplainQuestion, ExplainReceipt, KnowledgeCell, KnowledgeCellParams,
    KnowledgeState, LedgerAnchor, MissionId, Obligation, ObligationId, ObligationState,
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
    ReferenceProjectionSpec, ReferenceSituationPublication, project_reference_situation,
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
            max_events: 16,
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
    Ok(EventSection {
        cells,
        alternatives,
        residuals,
        lifecycle_claim,
        unknown,
        at_risk,
        warnings,
        proof_roots,
    })
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

/// The capsule, its proof roots, and the answer metadata compiled before projection.
struct CompiledSituation {
    capsule: SituationCapsule,
    proof_roots: BTreeSet<ContentDigest>,
    degradation: Vec<String>,
    warnings: Vec<String>,
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
    let deployment_handle = format!("fss://deployment/{site_digest}");

    let mut degradation = vec![
        "No durable agent session exists (session.open is not exposed): this capsule is bound \
         to a deterministic read-only session identity and persists nothing."
            .to_owned(),
        "The payload renders the fss-core SituationCapsule and reference publication sections; \
         situation_capsule.v1 fields without a Rust counterpart (objectiveContract, \
         attentionFrontier, meaningfulDelta, epistemicDebt, validity) are not emitted, and the \
         anchor keeps the LedgerAnchor shape."
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
    let mut cells = vec![
        cell(KnowledgeCellParams {
            claim_id: CLAIM_LEDGER_HEAD.to_owned(),
            statement: format!(
                "The authority ledger holds {} at commit {} (ledger epoch {}); committed deltas: {families}.",
                plural(snapshot.batch_count, "committed batch", "committed batches"),
                anchor.commit_sequence,
                anchor.ledger_epoch
            ),
            knowledge_state: KnowledgeState::Known,
            provenance: ProvenanceClass::Derived,
            hypothesis: None,
            evidence: vec![ledger_evidence],
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        })?,
        cell(KnowledgeCellParams {
            claim_id: CLAIM_IMPORTS.to_owned(),
            statement: format!(
                "{} retained at this anchor.",
                plural(
                    snapshot.completed_imports.len(),
                    "completed file import is",
                    "completed file imports are"
                )
            ),
            knowledge_state: KnowledgeState::Known,
            provenance: ProvenanceClass::Derived,
            hypothesis: None,
            evidence: if snapshot.completed_imports.is_empty() {
                vec![ledger_evidence]
            } else {
                snapshot.completed_imports.clone()
            },
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        })?,
        cell(KnowledgeCellParams {
            claim_id: CLAIM_EFFECT_JOURNAL.to_owned(),
            statement: if snapshot.effect_journal_present {
                format!(
                    "The durable effect journal holds {} and {} ({} open).",
                    plural(snapshot.operations.len(), "operation", "operations"),
                    plural(snapshot.obligations.len(), "obligation", "obligations"),
                    snapshot.open_obligations().len()
                )
            } else {
                "No durable effect journal exists, so no effect was ever prepared.".to_owned()
            },
            knowledge_state: KnowledgeState::Known,
            provenance: ProvenanceClass::Derived,
            hypothesis: None,
            evidence: vec![snapshot.effect_journal_digest],
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        })?,
        cell(KnowledgeCellParams {
            claim_id: CLAIM_COVERAGE.to_owned(),
            statement: "No CoverageWitness is retained: current site activity is not observable \
                        and absence is not certified."
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
    unknown.push(
        "Current site activity is not observable; a missing event is not absence.".to_owned(),
    );

    let mut alternatives = Vec::new();
    let mut residuals = vec![PossibleWorld {
        world_id: WORLD_UNOBSERVED_ACTIVITY.to_owned(),
        description: "Activity outside retained evidence remains possible.".to_owned(),
        claim_ids: BTreeSet::from([CLAIM_COVERAGE.to_owned()]),
        evidence: vec![anchor.state_root],
        consequence_severity: 4,
        protected: true,
    }];
    let mut coverage_handles = BTreeSet::from([format!("{deployment_handle}/coverage")]);
    let mut event_worlds: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for retained in &snapshot.events {
        let section = event_section(retained)?;
        let worlds: BTreeSet<String> = section
            .alternatives
            .iter()
            .chain(&section.residuals)
            .map(|world| world.world_id.clone())
            .collect();
        event_worlds.insert(retained.event.event_id.as_str().to_owned(), worlds);
        nominal.insert(section.lifecycle_claim.clone());
        cells.extend(section.cells);
        alternatives.extend(section.alternatives);
        residuals.extend(section.residuals);
        unknown.extend(section.unknown);
        at_risk.extend(section.at_risk);
        warnings.extend(section.warnings);
        proof_roots.extend(section.proof_roots);
        coverage_handles.insert(format!(
            "fss://event/{}/coverage",
            retained.event.event_id.as_str()
        ));
    }

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
        at_risk.push("fss doctor reports attention_required for this root.".to_owned());
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
    let mut affordances = vec![
        ListedAffordance {
            affordance_id: AFFORDANCE_REORIENT.to_owned(),
            operation: "session.orient",
            target: deployment_handle.clone(),
            rationale: format!(
                "Re-run `fss orient` after the ledger head advances past commit {}.",
                anchor.commit_sequence
            ),
            class: AffordanceClass::Wait,
            supported_worlds: all_worlds,
            required_capability: CAPABILITY_SITUATION_READ,
            cost: read_cost(snapshot.bytes_read, snapshot.files_read)?,
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
        for (event, worlds) in &event_worlds {
            affordances.push(
                ListedAffordance {
                    affordance_id: format!("{AFFORDANCE_EXPLAIN_PREFIX}{event}"),
                    operation: "explain",
                    target: format!("fss://event/{event}"),
                    rationale: format!(
                        "Explain evidence and knowledge state: `fss explain --event-id {event}`."
                    ),
                    class: AffordanceClass::Probe,
                    supported_worlds: worlds.clone(),
                    required_capability: CAPABILITY_EXPLAIN,
                    cost: read_cost(snapshot.bytes_read, snapshot.files_read)?,
                }
                .build(),
            );
        }
        affordances.push(
            ListedAffordance {
                affordance_id: AFFORDANCE_DOCTOR.to_owned(),
                operation: "doctor",
                target: format!("{deployment_handle}/doctor"),
                rationale: "Diagnose the root read-only: `fss doctor --json --root <dir>`."
                    .to_owned(),
                class: AffordanceClass::Probe,
                supported_worlds: BTreeSet::new(),
                required_capability: CAPABILITY_DOCTOR,
                cost: read_cost(snapshot.bytes_read, snapshot.files_read)?,
            }
            .build(),
        );
        affordances.push(
            ListedAffordance {
                affordance_id: AFFORDANCE_FOLLOW.to_owned(),
                operation: "session.follow",
                target: deployment_handle.clone(),
                rationale: "session.follow is not exposed by this build.".to_owned(),
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
                rationale:
                    "plan and commit are not exposed; no policy grants effect authority here."
                        .to_owned(),
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

    let corroborated = snapshot
        .events
        .iter()
        .filter(|retained| retained.corroborated())
        .count();
    let now = vec![format!(
        "Commit {}: {}, {} corroborated, {}, {} open.",
        anchor.commit_sequence,
        plural(snapshot.events.len(), "published event", "published events"),
        corroborated,
        plural(snapshot.completed_imports.len(), "import", "imports"),
        plural(obligation_ids.len(), "obligation", "obligations"),
    )];
    why.push(format!(
        "Compiled read-only from the committed ledger prefix (root {}) and effect journal.",
        snapshot.ledger_root
    ));

    let envelope_identity = digest_of("fss.reference_orient_worlds.v1", |encoder| {
        encoder.text(&objective_id);
        anchor.encode_canonical(encoder);
        encoder.u64(alternatives.len() as u64);
        for world in alternatives.iter().chain(&residuals) {
            world.encode_canonical(encoder);
        }
    });
    let world_envelope = WorldEnvelope {
        envelope_id: format!("world-envelope:{envelope_identity}"),
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
    let identity = digest_of("fss.reference_orient_capsule.v1", |encoder| {
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
        frame_id: format!("frame:{identity}"),
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
    Ok(CompiledSituation {
        capsule,
        proof_roots,
        degradation,
        warnings,
    })
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
/// Supported views are `pulse`, `brief`, and `epistemic_map`. The critical context (protected
/// worlds, epistemic boundaries, risks, obligations, next and blocked affordances) is never
/// truncated: if it does not fit the admitted budget the orientation is refused with
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
    let (publication, target_tokens) = match request.budget_tokens {
        Some(tokens) => match project_reference_situation(
            situation,
            &projection_spec(request.view, tokens, false)?,
        ) {
            Ok(publication) => (publication, tokens),
            Err(error) if is_budget_refusal(&error) => {
                return Err(OrientError::ContextBudgetExceeded {
                    view: request.view,
                    budget_tokens: tokens,
                });
            }
            Err(error) => return Err(error.into()),
        },
        None => match project_reference_situation(
            situation.clone(),
            &projection_spec(request.view, target, false)?,
        ) {
            Ok(publication) => (publication, target),
            Err(error) if is_budget_refusal(&error) => {
                match project_reference_situation(
                    situation,
                    &projection_spec(request.view, maximum, true)?,
                ) {
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
                }
            }
            Err(error) => return Err(error.into()),
        },
    };
    let capsule = &publication.situation.capsule;
    let projection = orient_projection(capsule, orient_budget(request.view)?)?;
    let epistemic_state = capsule
        .frame
        .knowledge_cells
        .iter()
        .map(KnowledgeCell::knowledge_state)
        .max_by_key(|state| severity_rank(*state))
        .unwrap_or(KnowledgeState::Unknown);
    let contradictions = capsule
        .frame
        .knowledge_cells
        .iter()
        .filter(|cell| {
            !cell.contradictions().is_empty()
                || cell.knowledge_state() == KnowledgeState::Conflicted
        })
        .map(|cell| cell.claim_id().to_owned())
        .collect();
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
    let open_obligations = capsule.obligations.clone();
    let mut indeterminate_effects: Vec<OperationId> = snapshot
        .indeterminate_operations()
        .iter()
        .map(|operation| operation.intent.operation_id.clone())
        .collect();
    indeterminate_effects.sort();
    Ok(DeploymentOrientation {
        view: request.view,
        projection,
        target_tokens,
        open_obligations,
        indeterminate_effects,
        degradation,
        warnings: compiled.warnings,
        contradictions,
        epistemic_state,
        requested,
        consumed,
        publication,
    })
}

/// One read-only explanation of a published event (AOP-011).
#[derive(Clone, Debug, PartialEq)]
pub struct EventExplanation {
    /// The retained event lineage explained.
    pub event: RetainedEvent,
    /// Bounded explain receipt binding the question, the event revision, and its evidence.
    pub receipt: ExplainReceipt,
    /// The event's knowledge cells, exactly as compiled into the capsule.
    pub cells: Vec<KnowledgeCell>,
    /// Retained worlds that name the event.
    pub worlds: Vec<PossibleWorld>,
    /// Affordance identities that target the event, plus the re-orient heartbeat.
    pub next_actions: Vec<String>,
    /// Observations that would change the event's knowledge state.
    pub would_change: Vec<String>,
    /// Assumptions the explanation rests on.
    pub assumptions: Vec<String>,
}

/// Explains one published event from a compiled `brief` orientation.
///
/// Returns `Ok(None)` when no committed `event_revision` delta names `event_id`.
pub fn explain_event(
    snapshot: &DeploymentSnapshot,
    orientation: &DeploymentOrientation,
    event_id: &EventId,
) -> Result<Option<EventExplanation>, OrientError> {
    let Some(retained) = snapshot.event(event_id) else {
        return Ok(None);
    };
    let prefix = format!("claim:event:{}:", event_id.as_str());
    let capsule = orientation.capsule();
    let cells: Vec<KnowledgeCell> = capsule
        .frame
        .knowledge_cells
        .iter()
        .filter(|cell| cell.claim_id().starts_with(&prefix))
        .cloned()
        .collect();
    let world_prefix = format!("world:event:{}:", event_id.as_str());
    let envelope = &capsule.frame.world_envelope;
    let worlds: Vec<PossibleWorld> = envelope
        .alternatives
        .iter()
        .chain(&envelope.adversarial_residuals)
        .filter(|world| world.world_id.starts_with(&world_prefix))
        .cloned()
        .collect();
    let target = format!("fss://event/{}", event_id.as_str());
    let mut next_actions: Vec<String> = capsule
        .affordances
        .iter()
        .filter(|candidate| {
            candidate.target == target || candidate.affordance_id == AFFORDANCE_REORIENT
        })
        .map(|candidate| candidate.affordance_id.clone())
        .collect();
    next_actions.sort();

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
        format!(
            "fss://event/{}/revision/{}",
            event_id.as_str(),
            event.revision
        ),
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
        cells,
        worlds,
        next_actions,
        would_change,
        assumptions,
    }))
}

#[cfg(test)]
mod tests;
