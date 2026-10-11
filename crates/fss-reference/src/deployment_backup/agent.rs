#![forbid(unsafe_code)]
//! Exact custody of the native agent journal and publications, without reviving authority.

use std::collections::BTreeSet;
use std::path::Path;

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, LedgerAnchor};
use fss_object::ObjectManifest;
use fss_publication::WriterDetectionOptions;

use crate::agent_session::checkpoint::journal::{
    DurableSessionLimits, SessionRecoveryState, inspect_session_bytes,
};
use crate::agent_session::work_claims::WorkClaimLimits;
use crate::deployment_session::{AgentRecoveryRecord, decode_recovery_record, publication_limits};

use super::io::ReadIo;
use super::manifest::{BackupFile, named_digest};
use super::{BackupError, BackupLimits, Result};

pub(super) const DIRECTORIES: &[&str] = &[
    "agent",
    "agent/sessions",
    "agent/publications",
    "agent/publications/roots",
    "agent/publications/tombstones",
    "agent/publications/spool",
    "agent/publications/spool/objects",
    "agent/publications/spool/staging",
    "agent/publications/spool/verified",
];
pub(super) const LOCKS: &[&str] = &[
    "agent/sessions/LOCK",
    "agent/publications/LOCK",
    "agent/publications/spool/LOCK",
];
const MAX_RECORD_BYTES: usize = 1024 * 1024;

/// Canonical recovery metadata, independently bound to all copied raw file bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentBackupSummary {
    /// Exact committed native session journal root.
    pub journal_root: ContentDigest,
    /// Exact committed journal byte length.
    pub journal_bytes: u64,
    /// Committed record count, including initialization.
    pub journal_records: u64,
    /// Session checkpoint including aliases and disclosure accounting.
    pub session_checkpoint: ContentDigest,
    /// Exact immutable workspace store checkpoint.
    pub workspace_checkpoint: ContentDigest,
    /// Retained sessions, including closed identities.
    pub session_count: u64,
    /// Explicit session closure or expiry tombstones.
    pub closed_session_count: u64,
    /// Every retained workspace revision, including superseded revisions.
    pub workspace_revision_count: u64,
    /// Historical claim heads; no lease is admitted by this count.
    pub claim_count: u64,
    /// Historical investigation heads.
    pub case_count: u64,
    /// Verified mission, handoff, plan, episode, finding and feedback roots.
    pub publication_count: u64,
    /// Commitment to every ordered publication slot, root and metadata digest.
    pub publication_digest: ContentDigest,
}

impl AgentBackupSummary {
    pub(super) fn encode(&self, e: &mut CanonicalEncoder) {
        e.digest(self.journal_root);
        e.u64(self.journal_bytes);
        e.u64(self.journal_records);
        e.digest(self.session_checkpoint);
        e.digest(self.workspace_checkpoint);
        e.u64(self.session_count);
        e.u64(self.closed_session_count);
        e.u64(self.workspace_revision_count);
        e.u64(self.claim_count);
        e.u64(self.case_count);
        e.u64(self.publication_count);
        e.digest(self.publication_digest);
    }

    pub(super) fn decode(d: &mut CanonicalDecoder<'_>, limits: BackupLimits) -> Result<Self> {
        let value = Self {
            journal_root: d.digest()?,
            journal_bytes: d.u64()?,
            journal_records: d.u64()?,
            session_checkpoint: d.digest()?,
            workspace_checkpoint: d.digest()?,
            session_count: d.u64()?,
            closed_session_count: d.u64()?,
            workspace_revision_count: d.u64()?,
            claim_count: d.u64()?,
            case_count: d.u64()?,
            publication_count: d.u64()?,
            publication_digest: d.digest()?,
        };
        let native = DurableSessionLimits::default();
        if value.journal_bytes == 0
            || value.journal_bytes > limits.max_journal_bytes.min(native.max_journal_bytes) as u64
            || value.journal_records == 0
            || value.journal_records > native.max_records as u64
            || value.session_count > native.sessions.max_sessions as u64
            || value.closed_session_count > value.session_count
            || value.workspace_revision_count > value.journal_records
            || value.claim_count > value.journal_records
            || value.case_count > value.journal_records
            || value.publication_count > 4096
        {
            return Err(BackupError::Limit("agent_state"));
        }
        Ok(value)
    }
}

/// One fully verified native publication, including the decoded historical record.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentPublicationState {
    /// Exact durable publication slot.
    pub slot: String,
    /// Existing native manifest kind.
    pub kind: String,
    /// Exact publication root.
    pub root: ContentDigest,
    /// Exact canonical metadata record digest.
    pub metadata_digest: ContentDigest,
    /// Complete ordered closure children, including metadata.
    pub children: Vec<ContentDigest>,
    /// Historical content decoded by its native record owner.
    pub record: AgentRecoveryRecord,
}

/// Original private agent state for inspection or disaster recovery, never live authority.
/// No session clock is advanced, claim renewed, handoff resumed, or effect prepared.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentRecoveryState {
    /// Current authority anchor of the inspected copy.
    pub source_anchor: LedgerAnchor,
    /// True when the canonical restoration fence is present.
    pub restored: bool,
    /// Canonical exact state metadata.
    pub summary: AgentBackupSummary,
    /// Full verified checkpoint and retained cognition history.
    pub sessions: SessionRecoveryState,
    /// Every native publication, sorted by slot.
    pub publications: Vec<AgentPublicationState>,
}

pub(super) fn inspect(
    root: &Path,
    anchor: &LedgerAnchor,
    restored: bool,
    files: &[BackupFile],
    deleted: &BTreeSet<ContentDigest>,
    limits: BackupLimits,
    io: &ReadIo<'_>,
) -> Result<AgentRecoveryState> {
    let journal_bytes = io.read_exact(
        &root.join("agent/sessions/journal.fssj"),
        limits.max_journal_bytes as u64,
    )?;
    let native_limits = DurableSessionLimits {
        max_journal_bytes: limits.max_journal_bytes,
        ..DurableSessionLimits::default()
    };
    let sessions = inspect_session_bytes(&journal_bytes, native_limits, WorkClaimLimits::default())
        .map_err(|_| BackupError::Corrupt("agent_journal"))?;
    if sessions.inspection.incomplete_tail.is_some()
        || sessions.inspection.committed_bytes != journal_bytes.len() as u64
    {
        return Err(BackupError::RecoveryRequired("agent_journal_tail"));
    }
    let pin = io.read_exact(&root.join("agent/sessions/ROOT"), 256)?;
    if pin != format!("{}\n", sessions.inspection.root.to_text()).as_bytes() {
        return Err(BackupError::RecoveryRequired("agent_root_pin"));
    }
    let workspace_checkpoint = sessions
        .workspace_checkpoint_digest
        .ok_or(BackupError::RecoveryRequired("agent_workspaces_missing"))?;
    if sessions
        .sessions
        .iter()
        .any(|state| state.session.current_anchor.site_lineage != anchor.site_lineage)
    {
        return Err(BackupError::Corrupt("agent_lineage"));
    }

    let directory = root.join("agent/publications");
    let local = fss_publication::inspect_with_io(
        io,
        &directory,
        publication_limits(),
        None,
        WriterDetectionOptions {
            probe_shared_lock: false,
            self_holds_lock: true,
        },
    );
    io.check()?;
    let local = local.map_err(|_| BackupError::Corrupt("agent_publication"))?;
    if !local.report.spool.is_clean()
        || !local.report.broken_roots.is_empty()
        || !local.report.foreign.is_empty()
        || local.missing_layout
        || local.spool_over_capacity
    {
        return Err(BackupError::Corrupt("agent_object_custody"));
    }
    if !local.report.orphaned_temps.is_empty()
        || !local.redundant_temps.is_empty()
        || local.holds_migration_pending
    {
        return Err(BackupError::RecoveryRequired(
            "agent_publication_incomplete",
        ));
    }
    let mut denied = deleted.clone();
    denied.extend(local.report.tombstones.iter().copied());
    for file in files {
        if let Some(name) = file.path.strip_prefix("agent/publications/spool/objects/")
            && denied.contains(&named_digest(name)?)
        {
            return Err(BackupError::RecoveryRequired("deleted_agent_bytes_remain"));
        }
    }
    let read = |digest| {
        let result =
            fss_publication::read_verified_with_io(&directory, digest, MAX_RECORD_BYTES, io);
        io.check()?;
        result.map_err(|_| BackupError::Corrupt("agent_record_custody"))
    };
    let mut publications = Vec::new();
    for visible in local.visible_roots() {
        let manifest = ObjectManifest::from_canonical_bytes(&read(visible.root)?)
            .map_err(|_| BackupError::Corrupt("agent_manifest"))?;
        let metadata_digest = manifest
            .metadata_digest()
            .ok_or(BackupError::Corrupt("agent_record_missing"))?;
        let record = decode_recovery_record(
            manifest.kind(),
            visible.slot.as_str(),
            &read(metadata_digest)?,
        )
        .map_err(|_| BackupError::Corrupt("agent_record"))?;
        if let AgentRecoveryRecord::Plan(plan) = &record
            && !manifest.children().contains(&plan.control_plan_digest)
        {
            return Err(BackupError::Corrupt("agent_plan_closure"));
        }
        publications.push(AgentPublicationState {
            slot: visible.slot.as_str().to_owned(),
            kind: manifest.kind().to_owned(),
            root: visible.root,
            metadata_digest,
            children: manifest.children().to_vec(),
            record,
        });
    }
    publications.sort_by(|a, b| a.slot.cmp(&b.slot));
    let mut e = CanonicalEncoder::new();
    e.text("fss.deployment_backup_agent_publications.v1");
    e.u64(publications.len() as u64);
    for publication in &publications {
        e.text(&publication.slot);
        e.digest(publication.root);
        e.digest(publication.metadata_digest);
    }
    let summary = AgentBackupSummary {
        journal_root: sessions.inspection.root,
        journal_bytes: sessions.inspection.committed_bytes,
        journal_records: sessions.inspection.records as u64,
        session_checkpoint: sessions.inspection.checkpoint_digest,
        workspace_checkpoint,
        session_count: sessions.sessions.len() as u64,
        closed_session_count: sessions
            .sessions
            .iter()
            .filter(|session| session.closed)
            .count() as u64,
        workspace_revision_count: sessions.workspace_revisions.len() as u64,
        claim_count: sessions.claims.len() as u64,
        case_count: sessions.cases.len() as u64,
        publication_count: publications.len() as u64,
        publication_digest: ContentDigest::sha256(&e.finish()),
    };
    io.check()?;
    Ok(AgentRecoveryState {
        source_anchor: anchor.clone(),
        restored,
        summary,
        sessions,
        publications,
    })
}
