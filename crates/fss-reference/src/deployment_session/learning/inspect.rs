#![forbid(unsafe_code)]
//! Exact, read-only recovery of one captured advisory candidate (AOP-011).
//!
//! A retained root is a selection handle, never authority. Current session admission precedes
//! all selected private reads. This path verifies only the chosen publication and the current
//! mission; it does not compile an orientation or enumerate the captured-learning inventory.

use std::collections::BTreeMap;
use std::fs::{self, File, TryLockError};
use std::io;
use std::path::{Path, PathBuf};

use fss_core::{AgentSession, AgentView, ContentDigest, LedgerAnchor, PrincipalId, SessionId};
use fss_object::ObjectManifest;
use fss_publication::{
    LOCAL_LOCK_FILE, LOCAL_ROOTS_DIR, LOCAL_TOMBSTONES_DIR, MAX_ROOT_RECORD_BYTES,
    ROOT_INDETERMINATE_SUFFIX, ROOT_RECORD_SUFFIX, ROOT_TEMP_SUFFIX, SlotName,
    TOMBSTONE_RECORD_SUFFIX, root_record_bytes,
};

use super::{
    MAX_CAPTURE_OBJECTS, MAX_RECORD_BYTES, MAX_SOURCE_BYTES, PlanRecord, PublishedLearning,
    decode_experience, hex, refused, verify_recovery_closure,
};
use crate::agent_follow::snapshot_anchor_token;
use crate::agent_orient::OrientError;
use crate::agent_session::ReferenceSessionError;
use crate::agent_session::checkpoint::journal::DurableSessionError;
use crate::agent_session::checkpoint::journal::projection::SessionProjection;
use crate::agent_session::workspace::WorkspaceRevision;
use crate::deployment_session::episode::EpisodeRecord;
use crate::deployment_session::feedback::decode_proposal;
use crate::deployment_session::orient::{AdmittedSessionRead, with_admitted_session_read};
use crate::deployment_session::{
    DeploymentSessionError, MissionRecord, PUBLICATIONS_RELPATH, evidence_now, read_bounded,
};

/// One exact immutable publication selected under a currently admitted session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectLearningRequest {
    /// Exact retained session; possession of its identity grants no access.
    pub session_id: SessionId,
    /// Caller whose current grants and private scope admit the read.
    pub principal: PrincipalId,
    /// Complete captured-learning publication root returned by feedback or orientation.
    pub publication_root: ContentDigest,
    /// Decision-diff or forensic response view; the retained session view is unchanged.
    pub view: AgentView,
    /// Optional response allowance within the selected view and remaining session grant.
    pub budget_tokens: Option<u64>,
}

/// Verified original candidate and source custody, accompanied by current read admission.
/// The candidate remains historical advisory data; this read creates no publication or review.
#[derive(Clone, Debug, PartialEq)]
pub struct LearningInspection {
    /// Exact original experience, proposal and source roots; committed is always false.
    pub learning: PublishedLearning,
    /// Unchanged currently admitted session; historical source grants confer no access.
    pub session: AgentSession,
    /// Unchanged current workspace, which may differ from the workspace used at capture.
    pub revision: WorkspaceRevision,
    /// Current deployment authority anchor, distinct from the captured experience's anchor.
    pub current_anchor: LedgerAnchor,
    /// Full current committed position, including the effect-journal prefix.
    pub current_anchor_token: String,
    /// Verified current immutable session-journal root.
    pub journal_root: ContentDigest,
    /// Original workspace digest authenticated by the retained capture binding.
    pub captured_workspace_digest: ContentDigest,
    /// Current deployment evidence time; never wall time or a renewed candidate deadline.
    pub observed_at_ns: i128,
    /// Remaining live session token allowance; this read does not spend or replenish it.
    pub remaining_tokens: u64,
    /// Response ceiling after clamping the default to the remaining live session allowance.
    pub effective_budget_tokens: u64,
    /// Measured byte lower bound: deployment prefix, session pin/journal and selected records.
    /// Additional layout/fence checks, metadata probes, replay and total CPU are unmetered.
    pub bytes_read: u64,
    /// File-read lower bound for the same retained prefix and selected record reads.
    pub files_read: u64,
    /// Exact verified learning-closure digests and payload lengths, including the root.
    /// These metadata artifacts do not grant source-media hydration.
    pub objects: Vec<(ContentDigest, u64)>,
}

fn unavailable() -> DeploymentSessionError {
    refused(
        "the requested captured learning is unavailable under this session or its retained custody; no advisory detail was disclosed",
    )
}

/// Inspect one captured candidate without replaying feedback, rebasing the workspace, spending
/// the session budget, repairing a ROOT pin, or opening any journal/publication writer.
/// The original candidate's full source graph is required; partial or foreign reads fail closed.
pub fn inspect_learning(
    root: &Path,
    request: &InspectLearningRequest,
) -> Result<LearningInspection, DeploymentSessionError> {
    if !matches!(request.view, AgentView::DecisionDiff | AgentView::Forensic) {
        return Err(OrientError::UnsupportedView(request.view).into());
    }
    let maximum = u64::from(request.view.maximum_tokens());
    if request
        .budget_tokens
        .is_some_and(|tokens| tokens == 0 || tokens > maximum)
    {
        return Err(OrientError::ContextBudgetExceeded {
            view: request.view,
            budget_tokens: request.budget_tokens.unwrap_or(0),
        }
        .into());
    }
    let (mut inspection, session_bytes, session_files) =
        with_admitted_session_read(root, &request.principal, &request.session_id, |read| {
            inspect_admitted(read, request)
        })?;
    inspection.bytes_read += session_bytes;
    inspection.files_read += session_files;
    Ok(inspection)
}

fn inspect_admitted(
    read: &AdmittedSessionRead<'_>,
    request: &InspectLearningRequest,
) -> Result<LearningInspection, DeploymentSessionError> {
    if !read.session.capabilities.contains("CAP-AGENT-EXPLAIN-001") {
        return Err(DurableSessionError::Session(ReferenceSessionError::GrantEscalation).into());
    }
    if read.remaining_tokens == 0
        || request
            .budget_tokens
            .is_some_and(|tokens| tokens > read.remaining_tokens)
    {
        return Err(DurableSessionError::Session(ReferenceSessionError::BudgetExceeded).into());
    }
    let default_budget = match request.view {
        AgentView::Forensic => 8_000,
        _ => u64::from(request.view.maximum_tokens()),
    };
    let effective_budget_tokens = request
        .budget_tokens
        .unwrap_or(default_budget)
        .min(read.remaining_tokens);
    let now = evidence_now(read.head);
    let sessions = read
        .store
        .recovery_state_for_projection(read.session, now)?;
    let directory = read.root.join(PUBLICATIONS_RELPATH);
    // This is the existing publisher lock, opened read-only. Holding it shared excludes a
    // cooperating standalone publisher as well as session writers excluded by the outer lock.
    // Drop closes the file and releases the lock on every return; no directory/file is created.
    let _publication_lock = shared_publication_lock(&directory)?;
    let mut reader = SelectedReader {
        directory,
        bytes_read: 0,
        files_read: 0,
    };
    verify_current_mission(&mut reader, read)?;

    let manifest_bytes = reader.object(request.publication_root, MAX_RECORD_BYTES)?;
    let manifest =
        ObjectManifest::from_canonical_bytes(&manifest_bytes).map_err(|_| unavailable())?;
    if manifest.kind() != "agent-learning"
        || manifest.root() != request.publication_root
        || manifest.children().len() > MAX_CAPTURE_OBJECTS
    {
        return Err(unavailable());
    }
    let metadata = manifest.metadata_digest().ok_or_else(unavailable)?;
    let experience_bytes = reader.object(metadata, MAX_RECORD_BYTES)?;
    let experience = decode_experience(&experience_bytes).map_err(|_| unavailable())?;
    if experience.mission_id != read.session.mission_id {
        return Err(unavailable());
    }
    let slot = SlotName::parse(&format!(
        "learning-{}",
        hex(ContentDigest::sha256(experience.experience_id.as_bytes()))
    ))
    .map_err(|_| unavailable())?;
    reader.visible(&slot, &manifest)?;

    let mut total_bytes = experience_bytes.len();
    let mut objects = BTreeMap::from([(metadata, experience_bytes)]);
    for digest in manifest.children() {
        if objects.contains_key(digest) {
            continue;
        }
        let remaining = (MAX_SOURCE_BYTES + 2 * MAX_RECORD_BYTES)
            .checked_sub(total_bytes)
            .ok_or_else(unavailable)?;
        let bytes = reader.object(*digest, MAX_RECORD_BYTES.min(remaining))?;
        total_bytes += bytes.len();
        objects.insert(*digest, bytes);
    }
    let verified = verify_recovery_closure(&experience, metadata, &objects, &sessions)
        .map_err(|_| unavailable())?;
    let binding = verified.binding;
    if binding.session_id != read.session.session_id
        || binding.mission_id != read.session.mission_id
        || binding.principal != read.session.principal_id
    {
        return Err(unavailable());
    }

    // The historical verifier already authenticates this episode and its original rendering.
    // Decode its exact retained resource-use field; do not reconstruct a new estimate at read time.
    let episode_manifest = objects
        .get(&binding.episode_root)
        .and_then(|bytes| ObjectManifest::from_canonical_bytes(bytes).ok())
        .ok_or_else(unavailable)?;
    let episode = episode_manifest
        .metadata_digest()
        .and_then(|digest| objects.get(&digest))
        .and_then(|bytes| EpisodeRecord::from_bytes(bytes).ok())
        .ok_or_else(unavailable)?;
    // A visible slot is mandatory even when an orphaned immutable object graph is retrievable.
    // Repeat its exact comparison before disclosure; no repair or durability promotion occurs.
    reader.visible(&slot, &manifest)?;
    verify_source_slots(&mut reader, &objects, &binding, &episode)?;
    reader.not_tombstoned(request.publication_root)?;
    for digest in objects.keys() {
        reader.not_tombstoned(*digest)?;
    }
    verify_current_mission(&mut reader, read)?;
    let captured_workspace_digest = binding.workspace_digest;
    let learning = PublishedLearning {
        contract_basis: binding.contract_basis,
        experience: verified.experience,
        proposal: verified.proposal,
        root: request.publication_root,
        experience_digest: metadata,
        proposal_digest: binding.proposal_digest,
        episode_root: binding.episode_root,
        feedback_root: binding.feedback_root,
        plan_root: binding.plan_root,
        committed: false,
        missing_evidence: binding.missing_evidence,
        evidence: binding.evidence,
        original_resource_use_json: episode.episode.resource_use_json,
    };
    objects.insert(request.publication_root, manifest_bytes);
    Ok(LearningInspection {
        learning,
        session: read.session.clone(),
        revision: read.revision.clone(),
        current_anchor: read.head.anchor.clone(),
        current_anchor_token: snapshot_anchor_token(read.head),
        journal_root: read.store.root(),
        captured_workspace_digest,
        observed_at_ns: now.0,
        remaining_tokens: read.remaining_tokens,
        effective_budget_tokens,
        bytes_read: read.head.bytes_read + reader.bytes_read,
        files_read: read.head.files_read + reader.files_read,
        objects: objects
            .into_iter()
            .map(|(digest, bytes)| (digest, bytes.len() as u64))
            .collect(),
    })
}

fn shared_publication_lock(directory: &Path) -> Result<File, DeploymentSessionError> {
    for relative in [LOCAL_ROOTS_DIR, LOCAL_TOMBSTONES_DIR] {
        let metadata = fs::symlink_metadata(directory.join(relative)).map_err(|_| unavailable())?;
        if !metadata.file_type().is_dir() {
            return Err(unavailable());
        }
    }
    let path = directory.join(LOCAL_LOCK_FILE);
    let metadata = fs::symlink_metadata(&path).map_err(|_| unavailable())?;
    if !metadata.file_type().is_file() {
        return Err(unavailable());
    }
    let lock = File::open(&path).map_err(|_| unavailable())?;
    match lock.try_lock_shared() {
        Ok(()) => Ok(lock),
        Err(TryLockError::WouldBlock) => Err(DeploymentSessionError::StoreLocked),
        Err(TryLockError::Error(_)) => Err(unavailable()),
    }
}

/// Selected-root reads deliberately do not call publication::inspect: its whole-spool scan
/// would make unrelated advisory inventory a prerequisite to recovering this exact candidate.
struct SelectedReader {
    directory: PathBuf,
    bytes_read: u64,
    files_read: u64,
}

impl SelectedReader {
    fn object(
        &mut self,
        digest: ContentDigest,
        maximum: usize,
    ) -> Result<Vec<u8>, DeploymentSessionError> {
        self.not_tombstoned(digest)?;
        let bytes = fss_publication::read_verified(&self.directory, digest, maximum)
            .map_err(|_| unavailable())?;
        self.bytes_read += bytes.len() as u64;
        self.files_read += 1;
        Ok(bytes)
    }

    /// A verified payload is not readable custody when its native deletion record exists.
    /// The native filename identifies the payload digest. Any retained/indeterminate/pending
    /// tombstone at that exact name fails closed, including malformed bytes or linked entries.
    fn not_tombstoned(&self, digest: ContentDigest) -> Result<(), DeploymentSessionError> {
        let name = digest.to_text().replacen(':', "-", 1);
        let tombstones = self.directory.join(LOCAL_TOMBSTONES_DIR);
        for suffix in ["", ROOT_INDETERMINATE_SUFFIX, ROOT_TEMP_SUFFIX] {
            let path = tombstones.join(format!("{name}{TOMBSTONE_RECORD_SUFFIX}{suffix}"));
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                _ => return Err(unavailable()),
            }
        }
        Ok(())
    }

    fn visible(
        &mut self,
        slot: &SlotName,
        manifest: &ObjectManifest,
    ) -> Result<(), DeploymentSessionError> {
        self.slot_record(slot, manifest, true)
    }

    fn slot_record(
        &mut self,
        slot: &SlotName,
        manifest: &ObjectManifest,
        required: bool,
    ) -> Result<(), DeploymentSessionError> {
        let roots = self.directory.join(LOCAL_ROOTS_DIR);
        for suffix in [ROOT_INDETERMINATE_SUFFIX, ROOT_TEMP_SUFFIX] {
            let marker = roots.join(format!("{slot}{ROOT_RECORD_SUFFIX}{suffix}"));
            match fs::symlink_metadata(marker) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                _ => return Err(unavailable()),
            }
        }
        let path = roots.join(format!("{slot}{ROOT_RECORD_SUFFIX}"));
        let Some(bytes) =
            read_bounded(&path, MAX_ROOT_RECORD_BYTES as usize).map_err(|_| unavailable())?
        else {
            return if required { Err(unavailable()) } else { Ok(()) };
        };
        self.bytes_read += bytes.len() as u64;
        self.files_read += 1;
        // The native publisher's canonical encoder fixes domain, checksum, version, slot, root,
        // child count and trailing-byte rules. Comparing complete bytes avoids a parallel parser.
        let expected = root_record_bytes(slot, manifest.root(), manifest.children().len())
            .map_err(|_| unavailable())?;
        if bytes != expected {
            return Err(unavailable());
        }
        Ok(())
    }
}

fn verify_current_mission(
    reader: &mut SelectedReader,
    read: &AdmittedSessionRead<'_>,
) -> Result<(), DeploymentSessionError> {
    let invalid = || {
        DeploymentSessionError::StoreInvalid(
            "the current workspace's mission publication is unavailable or inconsistent".to_owned(),
        )
    };
    let metadata =
        ContentDigest::parse(&read.revision.capsule().objective_digest).map_err(|_| invalid())?;
    let manifest =
        ObjectManifest::new("agent-mission", Vec::new(), Some(metadata)).map_err(|_| invalid())?;
    let manifest_bytes = reader
        .object(manifest.root(), MAX_RECORD_BYTES)
        .map_err(|_| invalid())?;
    let observed = ObjectManifest::from_canonical_bytes(&manifest_bytes).map_err(|_| invalid())?;
    if observed != manifest {
        return Err(invalid());
    }
    let record = reader
        .object(metadata, MAX_RECORD_BYTES)
        .map_err(|_| invalid())?;
    let mission = MissionRecord::from_bytes(&record).map_err(|_| invalid())?;
    if mission.digest() != metadata
        || mission.mission_id != read.session.mission_id
        || mission.session_id != read.session.session_id
        || mission.principal != read.session.principal_id
        || mission.site_lineage != read.session.current_anchor.site_lineage
    {
        return Err(invalid());
    }
    let slot = MissionRecord::slot(metadata).map_err(|_| invalid())?;
    reader.visible(&slot, &manifest).map_err(|_| invalid())
}

/// A learning root retains its own complete historical graph, so a source slot need not still
/// exist. An existing native source slot may not contradict that custody or be indeterminate.
fn verify_source_slots(
    reader: &mut SelectedReader,
    objects: &BTreeMap<ContentDigest, Vec<u8>>,
    binding: &super::recovery::CaptureBinding,
    episode: &EpisodeRecord,
) -> Result<(), DeploymentSessionError> {
    let manifest = |root: ContentDigest| {
        objects
            .get(&root)
            .and_then(|bytes| ObjectManifest::from_canonical_bytes(bytes).ok())
            .ok_or_else(unavailable)
    };
    let record = |manifest: &ObjectManifest| {
        manifest
            .metadata_digest()
            .and_then(|digest| objects.get(&digest))
            .ok_or_else(unavailable)
    };
    let plan_manifest = manifest(binding.plan_root)?;
    let plan = PlanRecord::from_bytes(record(&plan_manifest)?).map_err(|_| unavailable())?;
    let feedback_manifest = manifest(binding.feedback_root)?;
    let feedback = decode_proposal(record(&feedback_manifest)?).map_err(|_| unavailable())?;
    let episode_manifest = manifest(binding.episode_root)?;
    for (family, id, source) in [
        ("plan", plan.plan_id.as_str(), &plan_manifest),
        (
            "feedback",
            feedback.feedback_id.as_str(),
            &feedback_manifest,
        ),
        (
            "episode",
            episode.episode.episode_id.as_str(),
            &episode_manifest,
        ),
    ] {
        let slot = SlotName::parse(&format!(
            "{family}-{}",
            hex(ContentDigest::sha256(id.as_bytes()))
        ))
        .map_err(|_| unavailable())?;
        reader.slot_record(&slot, source, false)?;
    }
    let mission_manifest =
        ObjectManifest::new("agent-mission", Vec::new(), Some(binding.mission_digest))
            .map_err(|_| unavailable())?;
    let mission_slot = MissionRecord::slot(binding.mission_digest).map_err(|_| unavailable())?;
    reader.slot_record(&mission_slot, &mission_manifest, false)
}
