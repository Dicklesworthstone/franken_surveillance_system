#![forbid(unsafe_code)]
//! Bounded, owner-admitted discovery of immutable captured learning.
//!
//! Complete publication custody and original session/workspace membership are verified before
//! metadata is projected. Historical proposals remain advisory; no inventory read promotes,
//! renews, revives, executes or repairs anything.

use std::collections::BTreeMap;
use std::path::Path;

use fss_core::{AgentSession, ContentDigest, TimestampNs};
use fss_object::ObjectManifest;

use super::{
    MAX_CAPTURE_OBJECTS, MAX_RECORD_BYTES, decode_experience, hex, invalid, verify_recovery_closure,
};
use crate::agent_orient::OrientLearningBrief;
use crate::agent_session::checkpoint::journal::projection::SessionProjection;
use crate::deployment_session::{DeploymentSessionError, PUBLICATIONS_RELPATH, publication_limits};

/// Complete admitted inventories above this ceiling refuse; no successful page omits a capture.
pub const MAX_CAPTURED_LEARNING: usize = 16;
const MAX_SCAN_OBJECTS: usize = 512;
const MAX_SCAN_BYTES: usize = 8 * 1024 * 1024;

/// Compact protected context and the complete verified graphs a handoff must retain.
#[derive(Default)]
pub(crate) struct CapturedLearningInventory {
    pub(crate) briefs: Vec<OrientLearningBrief>,
    pub(crate) objects: BTreeMap<ContentDigest, Vec<u8>>,
}

fn read_object(
    directory: &Path,
    digest: ContentDigest,
    cache: &mut BTreeMap<ContentDigest, Vec<u8>>,
    total_bytes: &mut usize,
) -> Result<Vec<u8>, DeploymentSessionError> {
    if let Some(bytes) = cache.get(&digest) {
        return Ok(bytes.clone());
    }
    if cache.len() >= MAX_SCAN_OBJECTS || *total_bytes >= MAX_SCAN_BYTES {
        return Err(invalid(
            "complete captured-learning discovery exceeds its object or byte bound",
        ));
    }
    let bytes = fss_publication::read_verified(
        directory,
        digest,
        MAX_RECORD_BYTES.min(MAX_SCAN_BYTES - *total_bytes),
    )
    .map_err(|_| invalid("captured-learning custody is unavailable or corrupt"))?;
    *total_bytes = total_bytes
        .checked_add(bytes.len())
        .ok_or_else(|| invalid("captured-learning byte accounting overflow"))?;
    if *total_bytes > MAX_SCAN_BYTES {
        return Err(invalid(
            "complete captured-learning discovery exceeds its byte bound",
        ));
    }
    cache.insert(digest, bytes.clone());
    Ok(bytes)
}

/// The session journal owner excludes cooperating writers. Current read/privacy admission is
/// evaluated first; historical grant membership alone never authorizes these private records.
pub(crate) fn captured_inventory(
    root: &Path,
    store: &dyn SessionProjection,
    session: &AgentSession,
    now: TimestampNs,
) -> Result<CapturedLearningInventory, DeploymentSessionError> {
    let sessions = store
        .recovery_state_for_projection(session, now)
        .map_err(|error| invalid(format!("captured-learning session custody: {error}")))?;
    let directory = root.join(PUBLICATIONS_RELPATH);
    let metadata = std::fs::symlink_metadata(&directory)
        .map_err(|_| invalid("captured-learning publication inventory is unavailable"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid(
            "captured-learning publication inventory has an invalid layout",
        ));
    }
    let inspection = fss_publication::inspect(&directory, publication_limits())?;
    // Unreferenced immutable objects are not visible captures. They may remain after a failed
    // staging operation, but an incomplete layout, in-flight writer or damaged/foreign root
    // prevents a complete successful inventory. No recovery or cleanup runs here.
    if inspection.missing_layout
        || inspection.spool_over_capacity
        || inspection.possibly_stale
        || inspection.possibly_in_flight
        || !inspection.report.broken_roots.is_empty()
        || !inspection.report.foreign.is_empty()
    {
        return Err(invalid(
            "captured-learning publication inventory is incomplete or corrupt",
        ));
    }
    let mut result = CapturedLearningInventory::default();
    let mut cache = BTreeMap::new();
    let mut total_bytes = 0_usize;
    for visible in inspection.visible_roots() {
        if !visible.slot.as_str().starts_with("learning-") {
            continue;
        }
        let manifest_bytes = read_object(&directory, visible.root, &mut cache, &mut total_bytes)?;
        let manifest = ObjectManifest::from_canonical_bytes(&manifest_bytes)
            .map_err(|_| invalid("captured-learning manifest is malformed"))?;
        if manifest.root() != visible.root
            || manifest.kind() != "agent-learning"
            || manifest.children().len() > MAX_CAPTURE_OBJECTS
        {
            return Err(invalid(
                "captured-learning manifest differs from its registered profile",
            ));
        }
        let metadata = manifest
            .metadata_digest()
            .ok_or_else(|| invalid("captured-learning metadata is missing"))?;
        let mut objects = BTreeMap::new();
        for digest in manifest.children() {
            let bytes = read_object(&directory, *digest, &mut cache, &mut total_bytes)?;
            objects.insert(*digest, bytes);
        }
        let experience = decode_experience(
            objects
                .get(&metadata)
                .ok_or_else(|| invalid("captured-learning metadata is outside its closure"))?,
        )
        .map_err(|_| invalid("captured-learning experience is malformed"))?;
        if visible.slot.as_str()
            != format!(
                "learning-{}",
                hex(ContentDigest::sha256(experience.experience_id.as_bytes())),
            )
        {
            return Err(invalid(
                "captured-learning slot does not match its immutable identity",
            ));
        }
        let verified = verify_recovery_closure(&experience, metadata, &objects, &sessions)
            .map_err(|_| {
                invalid(
                    "captured-learning source closure or historical ownership failed verification",
                )
            })?;
        // Filtering follows authentication, so a corrupt or relabelled publication cannot
        // silently disappear behind an unverified foreign-owner field.
        if verified.binding.session_id != session.session_id
            || verified.binding.mission_id != session.mission_id
            || verified.binding.principal != session.principal_id
        {
            continue;
        }
        if experience.basis_anchor.site_lineage != session.current_anchor.site_lineage
            || experience.created_at_ns > now.0
        {
            return Err(invalid(
                "captured-learning deployment scope or evidence clock disagrees",
            ));
        }
        if result.briefs.len() == MAX_CAPTURED_LEARNING {
            return Err(invalid(
                "complete captured-learning inventory exceeds its protected-context bound",
            ));
        }
        let review_after_ns = verified
            .proposal
            .review_after_ns
            .ok_or_else(|| invalid("captured-learning review deadline is missing"))?;
        let expiry_ns = verified
            .proposal
            .expiry_ns
            .ok_or_else(|| invalid("captured-learning expiry deadline is missing"))?;
        result.briefs.push(OrientLearningBrief {
            experience_id: verified.experience.experience_id,
            proposal_id: verified.proposal.proposal_id,
            source_episode_id: verified.proposal.source_episode_id,
            class: verified.proposal.class,
            publication_root: visible.root,
            experience_digest: verified.binding.experience_digest,
            proposal_digest: verified.binding.proposal_digest,
            episode_root: verified.binding.episode_root,
            feedback_root: verified.binding.feedback_root,
            plan_root: verified.binding.plan_root,
            review_after: TimestampNs(review_after_ns),
            expires_at: TimestampNs(expiry_ns),
            review_due: now.0 >= review_after_ns,
            expired: now.0 >= expiry_ns,
            missing_evidence: verified.binding.missing_evidence,
        });
        result.objects.extend(objects);
        result.objects.insert(visible.root, manifest_bytes);
    }
    result
        .briefs
        .sort_by(|left, right| left.proposal_id.cmp(&right.proposal_id));
    if result
        .briefs
        .windows(2)
        .any(|pair| pair[0].proposal_id == pair[1].proposal_id)
    {
        return Err(invalid(
            "captured-learning inventory contains a duplicate immutable proposal",
        ));
    }
    Ok(result)
}
