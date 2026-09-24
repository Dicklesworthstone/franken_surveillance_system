#![forbid(unsafe_code)]
//! Durable agent sessions and root-last handoffs over a reference deployment root (AOP-001
//! `session.open`, AOP-012 `handoff`, AOP-002 `session.resume`).
//!
//! **Agent plane only.** Everything this module writes lives under `<root>/agent/`; the authority
//! ledger, the durable effect journal, and the deployment object spool are only read (through
//! [`DeploymentHistory`], exactly as `fss orient` reads them). No evidence, authority, or effect
//! record is ever created, and no affordance is ever executed.
//!
//! **Layout.**
//!
//! ```text
//! <root>/agent/sessions/LOCK           exclusive owner lock, held for one command
//! <root>/agent/sessions/journal.fssj   DurableSessionStore journal (sessions + workspaces)
//! <root>/agent/sessions/ROOT           pinned committed journal root (atomic replace)
//! <root>/agent/publications/           LocalRootPublisher: mission and handoff roots
//! ```
//!
//! Sessions and their immutable workspace revisions are persisted through the existing
//! [`DurableSessionStore`] (the crash-classifying session journal with workspace records).
//! The journal needs an independently pinned root to reopen; the pin is replaced atomically after
//! every commit. A pin that names an earlier committed record of the same journal (a crash
//! between the append and the pin replace) is advanced; any other mismatch (a rollback, a foreign
//! journal, a torn tail) is refused and never repaired here.
//!
//! Mission statements and handoffs are published root-last through [`LocalRootPublisher`]: the
//! record and its children are staged and verified, the root record is renamed into place last,
//! so a crash at any publication cut point leaves the root either absent or complete.
//!
//! **Clock.** Every time is the deployment's evidence clock (the latest committed evidence time,
//! as orientations use), never the wall clock, so equal committed bytes give equal answers.
//! Session leases and handoff lifetimes are measured on that clock.
//!
//! **Anchors.** A session is bound to the orientation anchor token it was opened (or last rebased)
//! at; its workspace revision records that token as the explicit anchor-bound assumption
//! [`ANCHOR_ASSUMPTION_ID`]. A handoff seals the situation as of the session's anchor with the
//! existing sealing code ([`seal_reference_publication_handoff`]). Resume resolves the handoff's
//! token against this deployment's committed history (a foreign or divergent history is refused),
//! compares the situation as of that anchor with the head through the reference meaningful-delta
//! engine, lists every invalidated assumption and anchor-bound fact, and rebases the session and
//! its workspace onto the head through the store's atomic refresh-and-rebase command.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use fss_core::{
    AgentSession, AgentSessionParams, AgentView, BudgetVector, CanonicalDecode, CanonicalDecoder,
    CanonicalEncode, CanonicalEncoder, ContentDigest, ContractBasis, ContractError, EffectState,
    HandoffCapsule, HandoffId, LedgerAnchor, MeaningfulDelta, MissionId, PrincipalId,
    SessionCapsule, SessionCapsuleParams, SessionId, TimestampNs,
};
use fss_object::{ObjectManifest, SpoolLimits};
use fss_publication::{
    LocalPublicationError, LocalPublicationLimits, LocalPublicationReceipt, LocalRootPublisher,
    PublishCutPoint, SlotName,
};

use crate::ReferenceError;
use crate::agent_follow::{
    AnchorRefusal, AnchorToken, FollowItem, follow_items, resolve_anchor, snapshot_anchor_token,
};
use crate::agent_orient::{
    DeploymentHistory, DeploymentOrientation, DeploymentReadError, DeploymentSnapshot, OrientError,
    OrientLimits, OrientRequest, OrientSessionBinding, orient_deployment_for,
};
use crate::agent_session::checkpoint::journal::workspace::{
    DurableWorkspaceError, JournaledWorkspace,
};
use crate::agent_session::checkpoint::journal::{
    DurableSessionError, DurableSessionLimits, DurableSessionStore, MAX_SESSION_JOURNAL_BYTES,
};
use crate::agent_session::workspace::{
    WorkspaceError, WorkspaceLimits, WorkspaceRevision, WorkspaceWrite, WorkspaceWriteMode,
};
use crate::agent_session::{ReferenceSessionError, SessionRefresh};
use crate::meaningful_delta::classify_reference_meaningful_delta;
use crate::situation_sections::{
    ReferenceSituationPublication, seal_reference_publication_handoff,
};

#[cfg(test)]
mod tests;

/// Agent-plane directory under a deployment root; nothing outside it is ever written.
pub const AGENT_DIR: &str = "agent";
/// Session journal directory, relative to the deployment root.
pub const SESSIONS_RELPATH: &str = "agent/sessions";
/// Mission and handoff publication directory, relative to the deployment root.
pub const PUBLICATIONS_RELPATH: &str = "agent/publications";
/// Session journal file name inside [`SESSIONS_RELPATH`].
pub const SESSION_JOURNAL_FILE: &str = "journal.fssj";
/// Pinned committed journal root file name inside [`SESSIONS_RELPATH`].
pub const SESSION_ROOT_PIN_FILE: &str = "ROOT";
/// Owner lock file name inside [`SESSIONS_RELPATH`].
pub const SESSION_LOCK_FILE: &str = "LOCK";
/// Session lease on the deployment evidence clock (seven days).
pub const SESSION_LEASE_NS: i128 = 7 * 24 * 3_600 * 1_000_000_000;
/// Handoff lifetime on the deployment evidence clock (seven days).
pub const HANDOFF_LIFETIME_NS: i128 = 7 * 24 * 3_600 * 1_000_000_000;
/// Agent-plane capabilities a session is negotiated with. None of them is an effect capability.
pub const SESSION_CAPABILITIES: [&str; 5] = [
    "CAP-AGENT-HANDOFF-READ-001",
    "CAP-AGENT-HANDOFF-WRITE-001",
    "CAP-AGENT-SESSION-READ-001",
    "CAP-AGENT-SESSION-WRITE-001",
    "CAP-AGENT-SITUATION-READ-001",
];
/// Privacy scope of every session (the only privacy class fss-core uses).
pub const SESSION_PRIVACY_SCOPE: &str = "private:property";
/// Statement identity of the workspace assumption naming the anchor token a session is bound to.
pub const ANCHOR_ASSUMPTION_ID: &str = "assumption:anchor-current";
/// Largest admitted mission statement.
pub const MAX_MISSION_BYTES: usize = 8192;
/// Largest admitted objective.
pub const MAX_OBJECTIVE_BYTES: usize = 4096;
/// Largest admitted handoff note.
pub const MAX_NOTE_BYTES: usize = 4096;
/// Largest admitted session token budget (the `agent_session.v1` bound).
pub const MAX_SESSION_TOKEN_BUDGET: u64 = 1_000_000;

const ANCHOR_ASSUMPTION_TEXT: &str = "The deployment head is the committed position ";
const MISSION_RECORD_DOMAIN: &str = "fss.reference_session_mission.v1";
const HANDOFF_RECORD_DOMAIN: &str = "fss.reference_session_handoff.v1";
const MAX_RECORD_BYTES: usize = 1024 * 1024;
const MAX_RECORD_ITEMS: usize = 4096;
const MAX_PIN_BYTES: usize = 256;

/// Why a session command was refused. Refusals never carry private payload bytes.
#[derive(Debug)]
pub enum DeploymentSessionError {
    /// The deployment itself could not be read.
    Read(DeploymentReadError),
    /// The situation could not be compiled.
    Orient(OrientError),
    /// Unknown, closed, expired, or another principal's session (deliberately indistinguishable).
    SessionUnknown,
    /// The session or workspace basis no longer admits the request.
    SessionStale(String),
    /// No handoff with that identity is published in this deployment.
    HandoffUnknown,
    /// The handoff is tampered, incomplete, expired, unauthorized, or foreign.
    HandoffInvalid(String),
    /// Another command holds the session store.
    StoreLocked,
    /// The agent-session store failed verification; it is never repaired implicitly.
    StoreInvalid(String),
    /// A contract or encoding invariant failed (an internal failure, never a partial answer).
    Internal(String),
}

impl fmt::Display for DeploymentSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(f, "{error}"),
            Self::Orient(error) => write!(f, "{error}"),
            Self::SessionUnknown => {
                f.write_str("the session is unknown, closed, expired, or held by another principal")
            }
            Self::SessionStale(reason) => write!(f, "session basis is stale: {reason}"),
            Self::HandoffUnknown => f.write_str("no handoff with that identity is published"),
            Self::HandoffInvalid(reason) => write!(f, "handoff refused: {reason}"),
            Self::StoreLocked => f.write_str("the agent-session store is held by another command"),
            Self::StoreInvalid(reason) => write!(f, "agent-session store refused: {reason}"),
            Self::Internal(reason) => write!(f, "internal failure: {reason}"),
        }
    }
}

impl std::error::Error for DeploymentSessionError {}

impl From<DeploymentReadError> for DeploymentSessionError {
    fn from(value: DeploymentReadError) -> Self {
        Self::Read(value)
    }
}

impl From<OrientError> for DeploymentSessionError {
    fn from(value: OrientError) -> Self {
        Self::Orient(value)
    }
}

impl From<ContractError> for DeploymentSessionError {
    fn from(value: ContractError) -> Self {
        Self::Internal(format!("contract: {value}"))
    }
}

impl From<ReferenceError> for DeploymentSessionError {
    fn from(value: ReferenceError) -> Self {
        Self::Internal(format!("reference: {value}"))
    }
}

impl From<DurableSessionError> for DeploymentSessionError {
    fn from(value: DurableSessionError) -> Self {
        match value {
            DurableSessionError::Session(ReferenceSessionError::Unavailable) => {
                Self::SessionUnknown
            }
            DurableSessionError::Session(error) => Self::SessionStale(error.to_string()),
            other => Self::StoreInvalid(other.to_string()),
        }
    }
}

impl From<DurableWorkspaceError> for DeploymentSessionError {
    fn from(value: DurableWorkspaceError) -> Self {
        match value {
            DurableWorkspaceError::Refused(WorkspaceError::Session(
                ReferenceSessionError::Unavailable,
            )) => Self::SessionUnknown,
            DurableWorkspaceError::Refused(error) => Self::SessionStale(error.to_string()),
            DurableWorkspaceError::Durability(error) => error.into(),
            other => Self::StoreInvalid(other.to_string()),
        }
    }
}

impl From<LocalPublicationError> for DeploymentSessionError {
    fn from(value: LocalPublicationError) -> Self {
        match value {
            LocalPublicationError::Locked { .. } => Self::StoreLocked,
            other => Self::StoreInvalid(format!("publication: {other}")),
        }
    }
}

fn io_failure(context: &str, error: &io::Error) -> DeploymentSessionError {
    DeploymentSessionError::StoreInvalid(format!("{context}: {error}"))
}

fn hex(value: ContentDigest) -> String {
    let text = value.to_text();
    text.split_once(':')
        .map_or(text.clone(), |(_, hex)| hex.to_owned())
}

fn digest_of(domain: &str, parts: impl FnOnce(&mut CanonicalEncoder)) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(domain);
    parts(&mut encoder);
    ContentDigest::sha256(&encoder.finish())
}

/// The evidence-clock time of a snapshot (never negative).
fn evidence_now(snapshot: &DeploymentSnapshot) -> TimestampNs {
    TimestampNs(snapshot.latest_evidence_time.0.max(0))
}

/// Canonical text of one workspace assumption: `<statement id>: <text>`.
fn assumption_entry(statement_id: &str, text: &str) -> String {
    format!("{statement_id}: {text}")
}

/// Splits a workspace assumption into its statement identity and text.
#[must_use]
pub fn split_assumption(entry: &str) -> (&str, &str) {
    entry.split_once(": ").unwrap_or((entry, entry))
}

/// The anchor token a workspace capsule is bound to (its [`ANCHOR_ASSUMPTION_ID`] assumption).
#[must_use]
pub fn capsule_anchor_token(capsule: &SessionCapsule) -> Option<&str> {
    capsule.assumptions.iter().find_map(|entry| {
        entry
            .strip_prefix(ANCHOR_ASSUMPTION_ID)?
            .strip_prefix(": ")?
            .strip_prefix(ANCHOR_ASSUMPTION_TEXT)?
            .strip_suffix('.')
    })
}

fn anchor_assumption(token: &str) -> String {
    assumption_entry(
        ANCHOR_ASSUMPTION_ID,
        &format!("{ANCHOR_ASSUMPTION_TEXT}{token}."),
    )
}

/// Every anchor-bound assumption an orientation rests on: the anchor token itself, then each
/// epistemic debt item of the orientation.
fn orientation_assumptions(orientation: &DeploymentOrientation) -> Vec<String> {
    let mut assumptions = vec![anchor_assumption(&orientation.anchor_token)];
    assumptions.extend(
        orientation
            .epistemic_debt
            .iter()
            .map(|item| assumption_entry(&item.debt_id, &item.assumption)),
    );
    assumptions
}

fn union(old: &[String], new: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out = old.to_vec();
    for item in new {
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

fn union_digests(
    old: &[ContentDigest],
    new: impl IntoIterator<Item = ContentDigest>,
) -> Vec<ContentDigest> {
    let mut out = old.to_vec();
    for item in new {
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Bounded canonical record helpers.
// ---------------------------------------------------------------------------------------------

fn encode_texts(encoder: &mut CanonicalEncoder, values: &[String]) {
    encoder.u64(values.len() as u64);
    for value in values {
        encoder.text(value);
    }
}

fn decode_texts(decoder: &mut CanonicalDecoder<'_>) -> Result<Vec<String>, ContractError> {
    let count = usize::try_from(decoder.u64()?).map_err(|_| ContractError::CountBoundExceeded)?;
    if count > MAX_RECORD_ITEMS {
        return Err(ContractError::CountBoundExceeded);
    }
    (0..count)
        .map(|_| decoder.text().map(str::to_owned))
        .collect()
}

fn encode_option(encoder: &mut CanonicalEncoder, value: Option<&str>) {
    match value {
        Some(text) => {
            encoder.bool(true);
            encoder.text(text);
        }
        None => encoder.bool(false),
    }
}

fn decode_option(decoder: &mut CanonicalDecoder<'_>) -> Result<Option<String>, ContractError> {
    Ok(if decoder.bool()? {
        Some(decoder.text()?.to_owned())
    } else {
        None
    })
}

// ---------------------------------------------------------------------------------------------
// Mission records.
// ---------------------------------------------------------------------------------------------

/// The durable mission statement a session serves, published root-last under `agent/`.
///
/// A private reference record format (like the session checkpoint), not a replacement for the
/// public `agent_mission.v1` schema: it retains exactly what the operator supplied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionRecord {
    /// Mission identity (derived from the deployment, mission statement, and objective).
    pub mission_id: MissionId,
    /// Session opened for this mission statement.
    pub session_id: SessionId,
    /// Principal that opened the session.
    pub principal: PrincipalId,
    /// Deployment site lineage.
    pub site_lineage: String,
    /// Mission statement, verbatim.
    pub mission: String,
    /// Objective, verbatim.
    pub objective: String,
    /// Anchor token of the orientation the session was opened at.
    pub opening_anchor_token: String,
    /// Registered view the session compiles situations in.
    pub view: AgentView,
    /// Session token budget.
    pub token_budget: u64,
    /// Opening time on the deployment evidence clock.
    pub created_at: TimestampNs,
}

impl MissionRecord {
    /// Canonical record bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(MISSION_RECORD_DOMAIN);
        self.mission_id.encode_canonical(&mut encoder);
        self.session_id.encode_canonical(&mut encoder);
        self.principal.encode_canonical(&mut encoder);
        encoder.text(&self.site_lineage);
        encoder.text(&self.mission);
        encoder.text(&self.objective);
        encoder.text(&self.opening_anchor_token);
        encoder.text(self.view.id());
        encoder.u64(self.token_budget);
        encoder.i128(self.created_at.0);
        encoder.finish()
    }

    /// Content identity of the record: the workspace objective digest.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }

    /// Decodes exactly canonical record bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(ContractError::CountBoundExceeded);
        }
        let mut decoder = CanonicalDecoder::new(bytes);
        if decoder.text()? != MISSION_RECORD_DOMAIN {
            return Err(ContractError::DigestMismatch);
        }
        let record = Self {
            mission_id: MissionId::parse(decoder.text()?)?,
            session_id: SessionId::parse(decoder.text()?)?,
            principal: PrincipalId::parse(decoder.text()?)?,
            site_lineage: decoder.text()?.to_owned(),
            mission: decoder.text()?.to_owned(),
            objective: decoder.text()?.to_owned(),
            opening_anchor_token: decoder.text()?.to_owned(),
            view: AgentView::from_id(decoder.text()?)?,
            token_budget: decoder.u64()?,
            created_at: TimestampNs(decoder.i128()?),
        };
        decoder.ensure_finished()?;
        if record.to_bytes() != bytes {
            return Err(ContractError::DigestMismatch);
        }
        Ok(record)
    }

    fn slot(digest: ContentDigest) -> Result<SlotName, DeploymentSessionError> {
        SlotName::parse(&format!("mission-{}", hex(digest)))
            .map_err(|_| DeploymentSessionError::Internal("mission slot name".to_owned()))
    }
}

// ---------------------------------------------------------------------------------------------
// Handoff records.
// ---------------------------------------------------------------------------------------------

/// A published handoff: the sealed [`HandoffCapsule`] plus everything a resumer needs without
/// conversational context. A private reference record format; its public rendering is
/// `agent_handoff_capsule.v1`.
#[derive(Clone, Debug, PartialEq)]
pub struct HandoffRecord {
    /// The root-closed handoff capsule sealed by [`seal_reference_publication_handoff`].
    pub capsule: HandoffCapsule,
    /// Anchor token of the committed position the handoff was sealed at.
    pub anchor_token: String,
    /// Registered view the situation was compiled in.
    pub view: AgentView,
    /// Decision fingerprint of the sealed situation capsule.
    pub situation_fingerprint: ContentDigest,
    /// Digest of the sealed situation publication.
    pub publication_digest: ContentDigest,
    /// Compression receipt of the sealed publication.
    pub compression_receipt_id: String,
    /// Context continuation of the sealed publication, when one exists.
    pub continuation: Option<String>,
    /// Workspace revision number handed off.
    pub workspace_revision: u64,
    /// Exact digest of that workspace revision.
    pub workspace_digest: ContentDigest,
    /// Session digest at the handoff.
    pub session_digest: ContentDigest,
    /// Session symbol-table generation at the handoff.
    pub symbol_table_generation: u64,
    /// Session token budget.
    pub token_budget: u64,
    /// Content identity of the mission record.
    pub mission_digest: ContentDigest,
    /// Operator note, verbatim.
    pub note: Option<String>,
    /// Workspace assumptions carried (`<statement id>: <text>`).
    pub assumptions: Vec<String>,
    /// Workspace assumptions already invalidated before the handoff (its epistemic debt).
    pub invalidated_assumptions: Vec<String>,
    /// Material unknowns of the situation.
    pub unknowns: Vec<String>,
    /// Open (pending or indeterminate) obligations at the anchor.
    pub obligations: Vec<String>,
    /// Operations whose external outcome is unresolved at the anchor.
    pub indeterminate_effects: Vec<String>,
    /// Operations prepared but not dispatched at the anchor.
    pub prepared_operations: Vec<String>,
    /// Next valid affordances of the situation (listed, never executed).
    pub recommended_affordances: Vec<String>,
    /// Observable changes that invalidate the handoff's situation.
    pub invalidators: Vec<String>,
    /// Privacy policy generation the situation is projected under.
    pub privacy_generation_id: String,
}

impl HandoffRecord {
    /// Canonical record bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let capsule = &self.capsule;
        let mut encoder = CanonicalEncoder::new();
        encoder.text(HANDOFF_RECORD_DOMAIN);
        capsule.handoff_id.encode_canonical(&mut encoder);
        capsule.mission_id.encode_canonical(&mut encoder);
        capsule.source_session_id.encode_canonical(&mut encoder);
        capsule.source_principal_id.encode_canonical(&mut encoder);
        capsule.anchor.encode_canonical(&mut encoder);
        encoder.digest(capsule.situation_capsule_root);
        encoder.u64(capsule.child_roots.len() as u64);
        for child in &capsule.child_roots {
            encoder.digest(*child);
        }
        encoder.digest(capsule.handoff_root);
        encoder.bytes(&capsule.contract_basis.try_canonical_bytes()?);
        encoder.i128(capsule.created_at.0);
        encoder.i128(capsule.expires_at.0);
        encoder.text(&self.anchor_token);
        encoder.text(self.view.id());
        encoder.digest(self.situation_fingerprint);
        encoder.digest(self.publication_digest);
        encoder.text(&self.compression_receipt_id);
        encode_option(&mut encoder, self.continuation.as_deref());
        encoder.u64(self.workspace_revision);
        encoder.digest(self.workspace_digest);
        encoder.digest(self.session_digest);
        encoder.u64(self.symbol_table_generation);
        encoder.u64(self.token_budget);
        encoder.digest(self.mission_digest);
        encode_option(&mut encoder, self.note.as_deref());
        for list in [
            &self.assumptions,
            &self.invalidated_assumptions,
            &self.unknowns,
            &self.obligations,
            &self.indeterminate_effects,
            &self.prepared_operations,
            &self.recommended_affordances,
            &self.invalidators,
        ] {
            encode_texts(&mut encoder, list);
        }
        encoder.text(&self.privacy_generation_id);
        encoder.finish_checked()
    }

    /// Decodes exactly canonical record bytes and verifies the handoff root and graph closure.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(ContractError::CountBoundExceeded);
        }
        let mut decoder = CanonicalDecoder::new(bytes);
        if decoder.text()? != HANDOFF_RECORD_DOMAIN {
            return Err(ContractError::DigestMismatch);
        }
        let handoff_id = HandoffId::parse(decoder.text()?)?;
        let mission_id = MissionId::parse(decoder.text()?)?;
        let source_session_id = SessionId::parse(decoder.text()?)?;
        let source_principal_id = PrincipalId::parse(decoder.text()?)?;
        let anchor = LedgerAnchor::decode_canonical(&mut decoder)?;
        let situation_capsule_root = decoder.digest()?;
        let children =
            usize::try_from(decoder.u64()?).map_err(|_| ContractError::CountBoundExceeded)?;
        if children > MAX_RECORD_ITEMS {
            return Err(ContractError::CountBoundExceeded);
        }
        let mut child_roots = BTreeSet::new();
        for _ in 0..children {
            child_roots.insert(decoder.digest()?);
        }
        let handoff_root = decoder.digest()?;
        let contract_basis = ContractBasis::from_canonical_bytes(decoder.bytes()?)?;
        let created_at = TimestampNs(decoder.i128()?);
        let expires_at = TimestampNs(decoder.i128()?);
        let capsule = HandoffCapsule {
            handoff_id,
            mission_id,
            source_session_id,
            source_principal_id,
            anchor,
            situation_capsule_root,
            child_roots,
            handoff_root,
            contract_basis,
            created_at,
            expires_at,
        };
        let anchor_token = decoder.text()?.to_owned();
        let view = AgentView::from_id(decoder.text()?)?;
        let situation_fingerprint = decoder.digest()?;
        let publication_digest = decoder.digest()?;
        let compression_receipt_id = decoder.text()?.to_owned();
        let continuation = decode_option(&mut decoder)?;
        let workspace_revision = decoder.u64()?;
        let workspace_digest = decoder.digest()?;
        let session_digest = decoder.digest()?;
        let symbol_table_generation = decoder.u64()?;
        let token_budget = decoder.u64()?;
        let mission_digest = decoder.digest()?;
        let note = decode_option(&mut decoder)?;
        let assumptions = decode_texts(&mut decoder)?;
        let invalidated_assumptions = decode_texts(&mut decoder)?;
        let unknowns = decode_texts(&mut decoder)?;
        let obligations = decode_texts(&mut decoder)?;
        let indeterminate_effects = decode_texts(&mut decoder)?;
        let prepared_operations = decode_texts(&mut decoder)?;
        let recommended_affordances = decode_texts(&mut decoder)?;
        let invalidators = decode_texts(&mut decoder)?;
        let privacy_generation_id = decoder.text()?.to_owned();
        decoder.ensure_finished()?;
        let record = Self {
            capsule,
            anchor_token,
            view,
            situation_fingerprint,
            publication_digest,
            compression_receipt_id,
            continuation,
            workspace_revision,
            workspace_digest,
            session_digest,
            symbol_table_generation,
            token_budget,
            mission_digest,
            note,
            assumptions,
            invalidated_assumptions,
            unknowns,
            obligations,
            indeterminate_effects,
            prepared_operations,
            recommended_affordances,
            invalidators,
            privacy_generation_id,
        };
        if record.to_bytes()? != bytes {
            return Err(ContractError::DigestMismatch);
        }
        // A consistently rewritten record still has to reproduce its sealed root.
        record.capsule.verify()?;
        Ok(record)
    }

    /// Publication slot of a handoff identity.
    pub fn slot(handoff_id: &HandoffId) -> Result<SlotName, DeploymentSessionError> {
        SlotName::parse(&format!(
            "handoff-{}",
            hex(ContentDigest::sha256(handoff_id.as_str().as_bytes()))
        ))
        .map_err(|_| DeploymentSessionError::Internal("handoff slot name".to_owned()))
    }
}

// ---------------------------------------------------------------------------------------------
// The agent-session journal and its pinned root.
// ---------------------------------------------------------------------------------------------

/// The deployment's session journal, held exclusively for the lifetime of one command.
#[derive(Debug)]
struct SessionJournal {
    directory: PathBuf,
    store: DurableSessionStore,
    _lock: File,
}

fn read_bounded(path: &Path, max: usize) -> Result<Option<Vec<u8>>, io::Error> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() || metadata.len() > max as u64 {
        return Err(io::Error::other("not a bounded regular file"));
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(io::Error::other("file exceeds its read bound"));
    }
    Ok(Some(bytes))
}

impl SessionJournal {
    fn open(root: &Path) -> Result<Self, DeploymentSessionError> {
        let directory = root.join(SESSIONS_RELPATH);
        fs::create_dir_all(&directory).map_err(|error| io_failure("session directory", &error))?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join(SESSION_LOCK_FILE))
            .map_err(|error| io_failure("session lock", &error))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(DeploymentSessionError::StoreLocked),
            Err(TryLockError::Error(error)) => return Err(io_failure("session lock", &error)),
        }
        let journal = directory.join(SESSION_JOURNAL_FILE);
        let pin = read_bounded(&directory.join(SESSION_ROOT_PIN_FILE), MAX_PIN_BYTES)
            .map_err(|error| io_failure("session root pin", &error))?
            .map(|bytes| {
                std::str::from_utf8(&bytes)
                    .ok()
                    .and_then(|text| ContentDigest::parse(text.trim_end()).ok())
                    .ok_or_else(|| {
                        DeploymentSessionError::StoreInvalid(
                            "the pinned session root is malformed".to_owned(),
                        )
                    })
            })
            .transpose()?;
        let limits = DurableSessionLimits::default();
        let mut store = match read_bounded(&journal, MAX_SESSION_JOURNAL_BYTES)
            .map_err(|error| io_failure("session journal", &error))?
        {
            None => {
                if pin.is_some() {
                    return Err(DeploymentSessionError::StoreInvalid(
                        "the pinned session journal is missing".to_owned(),
                    ));
                }
                DurableSessionStore::create(&journal, limits)?
            }
            Some(bytes) => {
                let report = fss_ledger::recover_bytes(&bytes).map_err(|error| {
                    DeploymentSessionError::StoreInvalid(format!("session journal: {error}"))
                })?;
                if report.incomplete_tail().is_some() {
                    return Err(DeploymentSessionError::StoreInvalid(
                        "the session journal ends in an incomplete append; explicit recovery is \
                         required"
                            .to_owned(),
                    ));
                }
                let last = report.last_root();
                let admitted = match pin {
                    // A crash between a committed append and the pin replace leaves the pin on
                    // an earlier committed record of this same journal.
                    Some(pinned) => {
                        pinned == last
                            || report
                                .records()
                                .iter()
                                .any(|record| record.root() == pinned)
                    }
                    // A crash inside creation: only the initial checkpoint and the workspace
                    // initialization can precede the first pin.
                    None => report.records().len() <= 2,
                };
                if !admitted {
                    return Err(DeploymentSessionError::StoreInvalid(
                        "the session journal does not extend its pinned root (rollback or \
                         foreign journal)"
                            .to_owned(),
                    ));
                }
                DurableSessionStore::open_existing(&journal, last, limits)?
            }
        };
        store.initialize_workspaces(WorkspaceLimits::default())?;
        let journal = Self {
            directory,
            store,
            _lock: lock,
        };
        journal.pin(pin)?;
        Ok(journal)
    }

    /// Atomically replaces the pinned root with the committed root when they differ.
    fn pin(&self, current: Option<ContentDigest>) -> Result<(), DeploymentSessionError> {
        let root = self.store.committed_root();
        if current == Some(root) {
            return Ok(());
        }
        let temporary = self.directory.join(format!("{SESSION_ROOT_PIN_FILE}.tmp"));
        let target = self.directory.join(SESSION_ROOT_PIN_FILE);
        let write = || -> io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temporary)?;
            file.write_all(format!("{}\n", root.to_text()).as_bytes())?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, &target)?;
            File::open(&self.directory)?.sync_all()
        };
        write().map_err(|error| io_failure("session root pin", &error))
    }

    fn commit_pin(&self) -> Result<(), DeploymentSessionError> {
        self.pin(None)
    }
}

// ---------------------------------------------------------------------------------------------
// Root-last agent publications.
// ---------------------------------------------------------------------------------------------

/// Bounds of the agent publication directory.
#[must_use]
pub fn publication_limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(4_096, 64, 64, 131_072, SpoolLimits::default())
}

fn publish_record(
    root: &Path,
    slot: &SlotName,
    kind: &str,
    record: &[u8],
    children: &[Vec<u8>],
    crash: Option<PublishCutPoint>,
) -> Result<LocalPublicationReceipt, DeploymentSessionError> {
    let mut publisher =
        LocalRootPublisher::open(root.join(PUBLICATIONS_RELPATH), publication_limits())?;
    let metadata = publisher.stage_object(record)?;
    let mut digests = Vec::with_capacity(children.len());
    for child in children {
        let digest = publisher.stage_object(child)?;
        if digest != metadata && !digests.contains(&digest) {
            digests.push(digest);
        }
    }
    let manifest = ObjectManifest::new(kind, digests, Some(metadata))
        .map_err(|error| DeploymentSessionError::Internal(format!("manifest: {error}")))?;
    if let Some(point) = crash {
        publisher.inject_crash_at(point);
    }
    Ok(publisher.publish(slot, &manifest)?)
}

/// One published agent root read back: its root and metadata record (every other child was
/// re-read and rehashed).
struct PublishedRecord {
    root: ContentDigest,
    record: Vec<u8>,
}

fn read_published(
    root: &Path,
    slot: &SlotName,
) -> Result<Option<PublishedRecord>, DeploymentSessionError> {
    let directory = root.join(PUBLICATIONS_RELPATH);
    if !directory.is_dir() {
        return Ok(None);
    }
    let inspection = fss_publication::inspect(&directory, publication_limits())?;
    if inspection.is_broken_slot(slot) {
        return Err(DeploymentSessionError::HandoffInvalid(format!(
            "the root in slot {slot} failed verification (tampered or incomplete)"
        )));
    }
    let Some(visible) = inspection.root(slot) else {
        return Ok(None);
    };
    let tampered = |what: &str| {
        DeploymentSessionError::HandoffInvalid(format!("{what} of slot {slot} failed verification"))
    };
    let manifest_bytes = fss_publication::read_verified(&directory, visible.root, MAX_RECORD_BYTES)
        .map_err(|_| tampered("the manifest"))?;
    let manifest = ObjectManifest::from_canonical_bytes(&manifest_bytes)
        .map_err(|_| tampered("the manifest"))?;
    if manifest.root() != visible.root {
        return Err(tampered("the manifest root"));
    }
    let metadata = manifest
        .metadata_digest()
        .ok_or_else(|| tampered("the record"))?;
    let record = fss_publication::read_verified(&directory, metadata, MAX_RECORD_BYTES)
        .map_err(|_| tampered("the record"))?;
    for child in manifest.children() {
        if *child != metadata {
            fss_publication::read_verified(&directory, *child, MAX_RECORD_BYTES)
                .map_err(|_| tampered("a child"))?;
        }
    }
    Ok(Some(PublishedRecord {
        root: visible.root,
        record,
    }))
}

fn read_mission(
    root: &Path,
    digest: ContentDigest,
) -> Result<MissionRecord, DeploymentSessionError> {
    let slot = MissionRecord::slot(digest)?;
    let published = read_published(root, &slot)
        .map_err(|error| match error {
            DeploymentSessionError::HandoffInvalid(reason) => {
                DeploymentSessionError::StoreInvalid(reason)
            }
            other => other,
        })?
        .ok_or_else(|| {
            DeploymentSessionError::StoreInvalid(
                "the session's mission record is not published".to_owned(),
            )
        })?;
    if ContentDigest::sha256(&published.record) != digest {
        return Err(DeploymentSessionError::StoreInvalid(
            "the mission record does not match its digest".to_owned(),
        ));
    }
    MissionRecord::from_bytes(&published.record)
        .map_err(|_| DeploymentSessionError::StoreInvalid("malformed mission record".to_owned()))
}

// ---------------------------------------------------------------------------------------------
// Situations.
// ---------------------------------------------------------------------------------------------

fn orient_bound(
    snapshot: &DeploymentSnapshot,
    view: AgentView,
    principal: &PrincipalId,
    mission_id: &MissionId,
    session_id: &SessionId,
    limits: &OrientLimits,
) -> Result<DeploymentOrientation, DeploymentSessionError> {
    let request = OrientRequest {
        view,
        principal: principal.clone(),
        budget_tokens: None,
    };
    let binding = OrientSessionBinding {
        mission_id: mission_id.clone(),
        session_id: session_id.clone(),
    };
    Ok(orient_deployment_for(
        snapshot,
        &request,
        limits,
        Some(&binding),
    )?)
}

/// Seals a projected orientation publication so it can be handed off.
///
/// An orientation with bound effect cells is already sealed by its compile path. Any other
/// orientation is sealed here, after projection, over its complete proof-root set; the
/// publication digest then commits to that seal. The capsule, bindings, and sections are
/// unchanged.
pub(crate) fn sealed_publication(
    mut publication: ReferenceSituationPublication,
) -> Result<ReferenceSituationPublication, ReferenceError> {
    if !publication.situation.is_sealed() {
        publication.situation.seal_effect_bindings()?;
        publication.publication_digest = publication.computed_digest()?;
    }
    publication.verify()?;
    Ok(publication)
}

/// The workspace capsule of `orientation` for `session`, carrying `previous` forward.
struct CapsuleInput<'a> {
    session: &'a AgentSession,
    revision: u64,
    objective_digest: &'a str,
    base_anchor: &'a LedgerAnchor,
    orientation: &'a DeploymentOrientation,
    previous: Option<&'a SessionCapsule>,
    mode: WorkspaceWriteMode,
}

fn workspace_capsule(input: &CapsuleInput<'_>) -> Result<SessionCapsule, ContractError> {
    let orientation = input.orientation;
    let capsule = orientation.capsule();
    let assumptions = orientation_assumptions(orientation);
    let unknowns = capsule.frame.unknown.clone();
    let not_observable = vec!["site activity outside retained evidence".to_owned()];
    let obligations: Vec<String> = orientation
        .open_obligations
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect();
    let bookmarked: Vec<ContentDigest> = orientation.proof_roots().iter().copied().collect();
    let next = capsule.frame.next.clone();
    let mut params = SessionCapsuleParams {
        session_id: input.session.session_id.clone(),
        revision: input.revision,
        principal: input.session.principal_id.as_str().to_owned(),
        capability_projection: input.session.capabilities.iter().cloned().collect(),
        objective_digest: input.objective_digest.to_owned(),
        base_anchor: input.base_anchor.clone(),
        current_anchor: capsule.anchor.clone(),
        situation_capsule_digest: capsule.decision_fingerprint()?.to_text(),
        active_hypotheses: Vec::new(),
        assumptions: Vec::new(),
        unknowns,
        not_observable_domains: not_observable,
        epistemic_debt: Vec::new(),
        open_obligations: obligations,
        budget_ledger: BudgetVector::builder()
            .tokens(input.session.token_budget)
            .build()
            .map_err(|_| ContractError::BudgetExhausted)?,
        bookmarked_evidence: bookmarked,
        next_actions: next,
        decision_digest: orientation.objective.decision_digest.clone(),
    };
    if let Some(old) = input.previous {
        // Every earlier assumption the fresh orientation does not restate becomes explicit
        // epistemic debt, never erased; a rebase moves all of them and invalidates every action.
        let moved: Vec<String> = old
            .assumptions
            .iter()
            .filter(|entry| {
                input.mode == WorkspaceWriteMode::Rebase || !assumptions.contains(entry)
            })
            .cloned()
            .collect();
        params.active_hypotheses = old.active_hypotheses.clone();
        params.unknowns = union(&old.unknowns, params.unknowns);
        params.not_observable_domains =
            union(&old.not_observable_domains, params.not_observable_domains);
        params.epistemic_debt = union(&old.epistemic_debt, moved);
        params.open_obligations = union(&old.open_obligations, params.open_obligations);
        params.bookmarked_evidence =
            union_digests(&old.bookmarked_evidence, params.bookmarked_evidence);
        params.next_actions = match input.mode {
            WorkspaceWriteMode::Rebase => Vec::new(),
            WorkspaceWriteMode::Advance => union(&old.next_actions, params.next_actions),
        };
    }
    params.assumptions = assumptions;
    SessionCapsule::new(params)
}

// ---------------------------------------------------------------------------------------------
// session.open
// ---------------------------------------------------------------------------------------------

/// One `session.open` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenSessionRequest {
    /// Mission statement, verbatim.
    pub mission: String,
    /// Objective, verbatim.
    pub objective: String,
    /// Opening principal (an audit label; no authority is minted).
    pub principal: PrincipalId,
    /// Registered orientation view (`pulse`, `brief`, or `epistemic_map`).
    pub view: AgentView,
    /// Cumulative session token budget (`1..=MAX_SESSION_TOKEN_BUDGET`).
    pub token_budget: u64,
}

/// A durable session opened (or exactly re-opened) at the head.
#[derive(Clone, Debug, PartialEq)]
pub struct OpenedSession {
    /// The durable session.
    pub session: AgentSession,
    /// The published mission record.
    pub mission: MissionRecord,
    /// Root of the mission publication.
    pub mission_root: ContentDigest,
    /// The first workspace revision.
    pub revision: WorkspaceRevision,
    /// The situation at the head, bound to the session.
    pub orientation: DeploymentOrientation,
    /// Committed session-journal root after the open.
    pub journal_root: ContentDigest,
    /// Canonical request digest.
    pub request_digest: ContentDigest,
}

fn open_identities(
    site: &str,
    request: &OpenSessionRequest,
    anchor_token: &str,
) -> Result<(MissionId, SessionId, ContentDigest), ContractError> {
    let mission = digest_of("fss.reference_session_mission_identity.v1", |encoder| {
        encoder.text(site);
        encoder.text(&request.mission);
        encoder.text(&request.objective);
    });
    let request_digest = digest_of("fss.reference_session_open_request.v1", |encoder| {
        encoder.text(site);
        encoder.text(&request.mission);
        encoder.text(&request.objective);
        request.principal.encode_canonical(encoder);
        encoder.text(request.view.id());
        encoder.u64(request.token_budget);
        encoder.text(anchor_token);
    });
    let short = |digest: ContentDigest| hex(digest).chars().take(32).collect::<String>();
    Ok((
        MissionId::parse(format!("mission:{}", short(mission)))?,
        SessionId::parse(format!("session:{}", short(request_digest)))?,
        request_digest,
    ))
}

fn validate_open(request: &OpenSessionRequest) -> Result<(), DeploymentSessionError> {
    let invalid = |reason: &str| DeploymentSessionError::Internal(reason.to_owned());
    if request.mission.is_empty() || request.mission.len() > MAX_MISSION_BYTES {
        return Err(invalid("mission statement size"));
    }
    if request.objective.is_empty() || request.objective.len() > MAX_OBJECTIVE_BYTES {
        return Err(invalid("objective size"));
    }
    if request.token_budget == 0 || request.token_budget > MAX_SESSION_TOKEN_BUDGET {
        return Err(invalid("token budget"));
    }
    Ok(())
}

/// Opens a durable, mission-scoped session at the deployment head (AOP-001).
///
/// The mission record is published root-last first, then the session and its revision-zero
/// workspace are committed to the session journal and the journal root is pinned. An identical
/// request at the same head is an exact retry: the existing session and revision are returned and
/// nothing new is committed.
pub fn open_session(
    root: &Path,
    request: &OpenSessionRequest,
) -> Result<OpenedSession, DeploymentSessionError> {
    validate_open(request)?;
    let limits = OrientLimits::default();
    let history = DeploymentHistory::read(root, &limits)?;
    let snapshot = history.snapshot_at(history.head())?;
    let token = snapshot_anchor_token(&snapshot);
    let (mission_id, session_id, request_digest) =
        open_identities(&snapshot.site_lineage, request, &token)?;
    let orientation = orient_bound(
        &snapshot,
        request.view,
        &request.principal,
        &mission_id,
        &session_id,
        &limits,
    )?;
    let now = evidence_now(&snapshot);
    let mission = MissionRecord {
        mission_id: mission_id.clone(),
        session_id: session_id.clone(),
        principal: request.principal.clone(),
        site_lineage: snapshot.site_lineage.clone(),
        mission: request.mission.clone(),
        objective: request.objective.clone(),
        opening_anchor_token: token,
        view: request.view,
        token_budget: request.token_budget,
        created_at: now,
    };
    let mission_digest = mission.digest();
    let mut journal = SessionJournal::open(root)?;
    let receipt = publish_record(
        root,
        &MissionRecord::slot(mission_digest)?,
        "agent-mission",
        &mission.to_bytes(),
        &[],
        None,
    )?;
    let capsule = orientation.capsule();
    let session = journal.store.open(
        AgentSessionParams {
            session_id: session_id.clone(),
            mission_id,
            principal_id: request.principal.clone(),
            capabilities: SESSION_CAPABILITIES
                .iter()
                .map(|cap| (*cap).to_owned())
                .collect(),
            privacy_scope: BTreeSet::from([SESSION_PRIVACY_SCOPE.to_owned()]),
            current_anchor: capsule.anchor.clone(),
            view_id: request.view.id().to_owned(),
            token_budget: request.token_budget,
            symbol_table_generation: 0,
            last_acknowledged_situation_fingerprint: Some(capsule.decision_fingerprint()?),
            created_at_ns: now.0,
            expires_at_ns: now.0.saturating_add(SESSION_LEASE_NS),
        },
        capsule.contract_basis.clone(),
        now,
    )?;
    let first = workspace_capsule(&CapsuleInput {
        session: &session,
        revision: 0,
        objective_digest: &mission_digest.to_text(),
        base_anchor: &capsule.anchor,
        orientation: &orientation,
        previous: None,
        mode: WorkspaceWriteMode::Advance,
    })?;
    let revision = journal
        .store
        .publish_workspace(
            &request.principal,
            WorkspaceWrite {
                expected_head: None,
                capsule: first,
                mode: WorkspaceWriteMode::Advance,
            },
            now,
        )?
        .result;
    journal.commit_pin()?;
    Ok(OpenedSession {
        session,
        mission,
        mission_root: receipt.root,
        revision,
        orientation,
        journal_root: journal.store.committed_root(),
        request_digest,
    })
}

// ---------------------------------------------------------------------------------------------
// handoff
// ---------------------------------------------------------------------------------------------

/// One `handoff` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffRequest {
    /// Session to hand off.
    pub session_id: SessionId,
    /// The session's principal.
    pub principal: PrincipalId,
    /// Operator note, verbatim.
    pub note: Option<String>,
}

/// A handoff sealed and ready to publish root-last; the session store stays held until
/// [`Self::publish`].
#[derive(Debug)]
pub struct PreparedHandoff {
    journal: SessionJournal,
    root: PathBuf,
    /// The record to publish.
    pub record: HandoffRecord,
    /// The session handed off, as read now.
    pub session: AgentSession,
    /// The workspace head handed off.
    pub workspace: WorkspaceRevision,
    /// The mission record.
    pub mission: MissionRecord,
    /// The sealed situation publication as of the session's anchor.
    pub publication: ReferenceSituationPublication,
    /// The orientation the publication was sealed from.
    pub orientation: DeploymentOrientation,
    /// Committed session-journal root when the handoff was prepared.
    pub journal_root: ContentDigest,
    /// Canonical request digest.
    pub request_digest: ContentDigest,
}

/// A published handoff.
#[derive(Clone, Debug, PartialEq)]
pub struct PublishedHandoff {
    /// The published record.
    pub record: HandoffRecord,
    /// Root-last publication receipt.
    pub receipt: LocalPublicationReceipt,
}

/// Seals a handoff of `request.session_id` as of the session's anchor (AOP-012). Nothing is
/// published until [`PreparedHandoff::publish`].
pub fn prepare_handoff(
    root: &Path,
    request: &HandoffRequest,
) -> Result<PreparedHandoff, DeploymentSessionError> {
    if request
        .note
        .as_ref()
        .is_some_and(|note| note.is_empty() || note.len() > MAX_NOTE_BYTES)
    {
        return Err(DeploymentSessionError::Internal("note size".to_owned()));
    }
    let limits = OrientLimits::default();
    let history = DeploymentHistory::read(root, &limits)?;
    let head = history.snapshot_at(history.head())?;
    let now = evidence_now(&head);
    let mut journal = SessionJournal::open(root)?;
    let session = journal
        .store
        .session(&request.principal, &request.session_id, now)?;
    let JournaledWorkspace {
        result: head_workspace,
        ..
    } = journal
        .store
        .workspace_head(&request.principal, &request.session_id, now)?;
    let workspace = head_workspace.revision;
    let capsule = workspace.capsule().clone();
    let mission = read_mission(root, ContentDigest::parse(&capsule.objective_digest)?)?;
    let token_text = capsule_anchor_token(&capsule).ok_or_else(|| {
        DeploymentSessionError::StoreInvalid(
            "the workspace names no anchor-bound position".to_owned(),
        )
    })?;
    let token = AnchorToken::parse(token_text).ok_or_else(|| {
        DeploymentSessionError::StoreInvalid("the workspace anchor token is malformed".to_owned())
    })?;
    let position = resolve_anchor(&history, &token).map_err(|refusal| {
        DeploymentSessionError::SessionStale(format!(
            "the session's anchor does not resolve in this deployment ({})",
            refusal.code()
        ))
    })?;
    let snapshot = history.snapshot_at(position)?;
    if snapshot.anchor != session.current_anchor {
        return Err(DeploymentSessionError::SessionStale(
            "the workspace anchor token and the session anchor disagree".to_owned(),
        ));
    }
    let orientation = orient_bound(
        &snapshot,
        session.view,
        &session.principal_id,
        &session.mission_id,
        &session.session_id,
        &limits,
    )?;
    let publication = sealed_publication(orientation.publication.clone())?;
    let situation = orientation.capsule();
    let handoff_id = HandoffId::parse(format!(
        "handoff:{}",
        hex(digest_of(
            "fss.reference_session_handoff_identity.v1",
            |encoder| {
                session.session_id.encode_canonical(encoder);
                encoder.digest(workspace.digest());
                encoder.text(token.as_str());
                encode_option(encoder, request.note.as_deref());
                encoder.i128(now.0);
            }
        ))
        .chars()
        .take(32)
        .collect::<String>()
    ))?;
    let sealed = seal_reference_publication_handoff(
        &publication,
        handoff_id,
        now,
        TimestampNs(now.0.saturating_add(HANDOFF_LIFETIME_NS)),
    )?;
    let open_obligations = snapshot
        .open_obligations()
        .iter()
        .map(|obligation| obligation.obligation_id.as_str().to_owned())
        .collect();
    let indeterminate = orientation
        .indeterminate_effects
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect();
    let prepared = snapshot
        .operations
        .iter()
        .filter(|operation| operation.state == EffectState::Prepared)
        .map(|operation| operation.intent.operation_id.as_str().to_owned())
        .collect();
    let record = HandoffRecord {
        capsule: sealed,
        anchor_token: token.as_str().to_owned(),
        view: session.view,
        situation_fingerprint: situation.decision_fingerprint()?,
        publication_digest: publication.publication_digest,
        compression_receipt_id: publication.compression_receipt.receipt_id.clone(),
        continuation: publication.context_pack.continuation.clone(),
        workspace_revision: capsule.revision,
        workspace_digest: workspace.digest(),
        session_digest: session.session_digest(),
        symbol_table_generation: session.symbol_table_generation,
        token_budget: session.token_budget,
        mission_digest: mission.digest(),
        note: request.note.clone(),
        assumptions: capsule.assumptions.clone(),
        invalidated_assumptions: capsule.epistemic_debt.clone(),
        unknowns: situation.frame.unknown.clone(),
        obligations: open_obligations,
        indeterminate_effects: indeterminate,
        prepared_operations: prepared,
        recommended_affordances: situation.frame.next.clone(),
        invalidators: orientation.validity.invalidators.clone(),
        privacy_generation_id: orientation.privacy_generation_id.clone(),
    };
    let request_digest = digest_of("fss.reference_session_handoff_request.v1", |encoder| {
        request.session_id.encode_canonical(encoder);
        request.principal.encode_canonical(encoder);
        encode_option(encoder, request.note.as_deref());
        head.anchor.encode_canonical(encoder);
    });
    journal.commit_pin()?;
    let journal_root = journal.store.committed_root();
    Ok(PreparedHandoff {
        journal,
        root: root.to_path_buf(),
        record,
        session,
        workspace,
        mission,
        publication,
        orientation,
        journal_root,
        request_digest,
    })
}

impl PreparedHandoff {
    /// Publishes the record root-last, with `children` (the rendered public projections) staged
    /// and verified beside it. Republishing an identical handoff is idempotent.
    pub fn publish(self, children: &[Vec<u8>]) -> Result<PublishedHandoff, DeploymentSessionError> {
        self.publish_at(children, None)
    }

    /// [`Self::publish`] with a crash injected at one publication cut point (tests only).
    pub(crate) fn publish_at(
        self,
        children: &[Vec<u8>],
        crash: Option<PublishCutPoint>,
    ) -> Result<PublishedHandoff, DeploymentSessionError> {
        let bytes = self.record.to_bytes()?;
        let receipt = publish_record(
            &self.root,
            &HandoffRecord::slot(&self.record.capsule.handoff_id)?,
            "agent-handoff",
            &bytes,
            children,
            crash,
        )?;
        drop(self.journal);
        Ok(PublishedHandoff {
            record: self.record,
            receipt,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// session.resume
// ---------------------------------------------------------------------------------------------

/// One `session.resume` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumeRequest {
    /// Published handoff to accept.
    pub handoff_id: HandoffId,
    /// Resuming principal; it must be in the handoff's recipient scope.
    pub principal: PrincipalId,
}

/// An accepted handoff rebased onto the head.
#[derive(Clone, Debug, PartialEq)]
pub struct ResumedSession {
    /// The accepted handoff.
    pub handoff: HandoffRecord,
    /// Root of the handoff publication.
    pub handoff_publication_root: ContentDigest,
    /// The mission record.
    pub mission: MissionRecord,
    /// The session after the resume.
    pub session: AgentSession,
    /// The workspace revision the handoff named.
    pub handed_off: WorkspaceRevision,
    /// The workspace head after the resume.
    pub revision: WorkspaceRevision,
    /// Whether this resume committed a new workspace revision.
    pub committed: bool,
    /// Situation as of the handoff anchor, bound to the session.
    pub basis: DeploymentOrientation,
    /// Situation at the head, bound to the session.
    pub result: DeploymentOrientation,
    /// The reference engine's delta from the handoff anchor to the head.
    pub delta: MeaningfulDelta,
    /// Every item of the delta, protected items first.
    pub items: Vec<FollowItem>,
    /// Every assumption, anchor-bound fact, and action invalidated since the handoff anchor.
    pub invalidated: Vec<String>,
    /// Whether the committed position moved since the handoff anchor.
    pub anchor_moved: bool,
    /// Committed session-journal root after the resume.
    pub journal_root: ContentDigest,
    /// Canonical request digest.
    pub request_digest: ContentDigest,
}

fn handoff_refusal(refusal: AnchorRefusal) -> DeploymentSessionError {
    DeploymentSessionError::HandoffInvalid(match refusal {
        AnchorRefusal::Foreign => {
            "the handoff was sealed in another deployment (foreign site lineage)".to_owned()
        }
        AnchorRefusal::Ahead => {
            "the handoff anchor lies past this deployment's committed head".to_owned()
        }
        AnchorRefusal::Unknown => {
            "the handoff anchor is not in this deployment's committed history".to_owned()
        }
    })
}

/// Everything invalidated between the handoff and the head, in a fixed order: the handoff's
/// workspace assumptions, its next actions, then the engine's protected changes and changed cells.
fn invalidations(
    handed_off: &SessionCapsule,
    handoff: &HandoffRecord,
    head_token: &str,
    delta: &MeaningfulDelta,
) -> Vec<String> {
    let mut out = Vec::new();
    for entry in &handed_off.assumptions {
        let (statement, text) = split_assumption(entry);
        out.push(format!(
            "assumption {statement} invalidated: \"{text}\" was bound to {} and the head is now {head_token}",
            handoff.anchor_token
        ));
    }
    for action in &handed_off.next_actions {
        out.push(format!(
            "next action {action} invalidated: it was listed at {} and must be re-derived at the head",
            handoff.anchor_token
        ));
    }
    out.extend(
        delta
            .invalidated_assumptions
            .iter()
            .map(|text| format!("engine: {text}")),
    );
    out.extend(
        delta
            .obligation_changes
            .iter()
            .map(|text| format!("obligation change: {text}")),
    );
    out.extend(
        delta
            .effect_uncertainty_changes
            .iter()
            .map(|text| format!("effect uncertainty change: {text}")),
    );
    out.extend(
        delta
            .removed_claim_ids
            .iter()
            .map(|claim| format!("claim {claim} removed")),
    );
    out.extend(delta.changed_cells.iter().map(|cell| {
        format!(
            "claim {} changed: now {} ({})",
            cell.claim_id(),
            cell.knowledge_state().as_str(),
            cell.disclosable_statement()
        )
    }));
    out
}

/// Accepts a published handoff and rebases its session onto the head (AOP-002).
///
/// Refuses an unknown handoff, a tampered or incomplete publication, an expired handoff, a
/// principal outside its recipient scope, and a handoff whose anchor does not resolve in this
/// deployment's committed history or whose session is not in this deployment's session journal
/// (foreign). When the committed position moved, the situation as of the handoff anchor is
/// compared with the head through the reference delta engine, every invalidated assumption and
/// anchor-bound fact is listed, and the session and workspace are rebased onto the head in one
/// atomic journal command. Resuming the same handoff again rebases nothing new.
pub fn resume_session(
    root: &Path,
    request: &ResumeRequest,
) -> Result<ResumedSession, DeploymentSessionError> {
    let limits = OrientLimits::default();
    let history = DeploymentHistory::read(root, &limits)?;
    let head = history.snapshot_at(history.head())?;
    let now = evidence_now(&head);
    let published = read_published(root, &HandoffRecord::slot(&request.handoff_id)?)?
        .ok_or(DeploymentSessionError::HandoffUnknown)?;
    let handoff = HandoffRecord::from_bytes(&published.record).map_err(|error| {
        DeploymentSessionError::HandoffInvalid(format!(
            "the handoff record does not verify: {error}"
        ))
    })?;
    if handoff.capsule.handoff_id != request.handoff_id {
        return Err(DeploymentSessionError::HandoffInvalid(
            "the published record names another handoff".to_owned(),
        ));
    }
    if handoff.capsule.source_principal_id != request.principal {
        return Err(DeploymentSessionError::HandoffInvalid(
            "the resuming principal is outside the handoff's recipient scope".to_owned(),
        ));
    }
    if now >= handoff.capsule.expires_at {
        return Err(DeploymentSessionError::HandoffInvalid(
            "the handoff expired on the deployment evidence clock".to_owned(),
        ));
    }
    let token = AnchorToken::parse(&handoff.anchor_token).ok_or_else(|| {
        DeploymentSessionError::HandoffInvalid("the handoff anchor token is malformed".to_owned())
    })?;
    let position = resolve_anchor(&history, &token).map_err(handoff_refusal)?;
    let basis_snapshot = history.snapshot_at(position)?;
    if basis_snapshot.anchor != handoff.capsule.anchor {
        return Err(DeploymentSessionError::HandoffInvalid(
            "the handoff anchor does not match this deployment's committed anchor".to_owned(),
        ));
    }
    let mut journal = SessionJournal::open(root)?;
    let principal = &handoff.capsule.source_principal_id;
    let session_id = &handoff.capsule.source_session_id;
    let session = journal
        .store
        .session(principal, session_id, now)
        .map_err(|error| match DeploymentSessionError::from(error) {
            DeploymentSessionError::SessionUnknown => DeploymentSessionError::HandoffInvalid(
                "the handoff's session is not open in this deployment (foreign, closed, or \
                 expired)"
                    .to_owned(),
            ),
            other => other,
        })?;
    if session.mission_id != handoff.capsule.mission_id {
        return Err(DeploymentSessionError::HandoffInvalid(
            "the handoff's mission is not the session's mission".to_owned(),
        ));
    }
    let handed_off = journal
        .store
        .resume_workspace(principal, session_id, handoff.workspace_digest, now)
        .map_err(|error| match DeploymentSessionError::from(error) {
            DeploymentSessionError::SessionStale(_) | DeploymentSessionError::SessionUnknown => {
                DeploymentSessionError::HandoffInvalid(
                    "the handoff's workspace revision is not in this session's history".to_owned(),
                )
            }
            other => other,
        })?
        .result
        .revision;
    let mission = read_mission(root, handoff.mission_digest)?;
    let basis = orient_bound(
        &basis_snapshot,
        handoff.view,
        principal,
        &session.mission_id,
        session_id,
        &limits,
    )?;
    let result = orient_bound(
        &head,
        handoff.view,
        principal,
        &session.mission_id,
        session_id,
        &limits,
    )?;
    let delta = classify_reference_meaningful_delta(&basis.publication, &result.publication)?;
    let items = follow_items(&delta);
    let anchor_moved = position != head.position;
    let invalidated = if anchor_moved {
        invalidations(handed_off.capsule(), &handoff, &result.anchor_token, &delta)
    } else {
        Vec::new()
    };

    let current = journal
        .store
        .workspace_head(principal, session_id, now)?
        .result
        .revision;
    let old = current.capsule().clone();
    let head_anchor = result.capsule().anchor.clone();
    let mut committed = false;
    let revision = if capsule_anchor_token(&old) == Some(result.anchor_token.as_str()) {
        current
    } else {
        let next = old
            .revision
            .checked_add(1)
            .ok_or_else(|| DeploymentSessionError::Internal("workspace revision".to_owned()))?;
        let mode = if head_anchor == session.current_anchor {
            WorkspaceWriteMode::Advance
        } else {
            WorkspaceWriteMode::Rebase
        };
        let capsule = workspace_capsule(&CapsuleInput {
            session: &session,
            revision: next,
            objective_digest: &old.objective_digest,
            base_anchor: &old.base_anchor,
            orientation: &result,
            previous: Some(&old),
            mode,
        })?;
        let write = WorkspaceWrite {
            expected_head: Some(current.digest()),
            capsule,
            mode,
        };
        committed = true;
        match mode {
            WorkspaceWriteMode::Rebase => {
                journal
                    .store
                    .rebase_workspace(
                        principal,
                        SessionRefresh {
                            expected_session_digest: session.session_digest(),
                            current_anchor: head_anchor,
                            capabilities: session.capabilities.clone(),
                            privacy_scope: session.privacy_scope.clone(),
                        },
                        write,
                        now,
                    )?
                    .result
            }
            WorkspaceWriteMode::Advance => {
                journal
                    .store
                    .publish_workspace(principal, write, now)?
                    .result
            }
        }
    };
    let session = journal.store.session(principal, session_id, now)?;
    journal.commit_pin()?;
    let request_digest = digest_of("fss.reference_session_resume_request.v1", |encoder| {
        request.handoff_id.encode_canonical(encoder);
        request.principal.encode_canonical(encoder);
        head.anchor.encode_canonical(encoder);
    });
    Ok(ResumedSession {
        handoff,
        handoff_publication_root: published.root,
        mission,
        session,
        handed_off,
        revision,
        committed,
        basis,
        result,
        delta,
        items,
        invalidated,
        anchor_moved,
        journal_root: journal.store.committed_root(),
        request_digest,
    })
}
