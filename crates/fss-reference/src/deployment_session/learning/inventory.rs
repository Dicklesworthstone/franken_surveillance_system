#![forbid(unsafe_code)]
//! Bounded, owner-admitted discovery of immutable captured learning.
//!
//! Complete publication custody and original session/workspace membership are verified before
//! metadata is projected. Historical proposals remain advisory; no inventory read promotes,
//! renews, revives, executes or repairs anything.
//!
//! Inventories above [`CAPTURED_LEARNING_SUMMARY_LIMIT`] never fail session open or feedback with
//! a store-invalid error: every `learning-*` root is still verified for tamper/rehash/symlink
//! integrity and duplicate identity, while protected context receives a deterministic bounded
//! top-N recent summary with explicit `total_captured_count`, `omitted_count`, and pagination
//! cursor metadata.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fss_core::{AgentSession, ContentDigest, TimestampNs};
use fss_object::ObjectManifest;

use super::{
    MAX_CAPTURE_OBJECTS, MAX_RECORD_BYTES, decode_experience, hex, invalid, verify_recovery_closure,
};
use crate::agent_orient::OrientLearningBrief;
use crate::agent_session::checkpoint::journal::projection::SessionProjection;
use crate::deployment_session::{DeploymentSessionError, PUBLICATIONS_RELPATH, publication_limits};

/// Maximum admitted captured-learning publications indexed per deployment session, aligned with
/// `publication_limits().max_roots`.
pub const MAX_CAPTURED_LEARNING: usize = 4_096;
/// Maximum recent captured-learning briefs projected directly into protected orientation context.
/// Additional verified captures remain accessible via deterministic cursor pagination.
pub const CAPTURED_LEARNING_SUMMARY_LIMIT: usize = 16;

/// Bounded per-scan read cache capacity (shared immutable objects such as plan/episode/mission
/// stay cached without allowing unbounded RAM growth across 500+ proposals).
const MAX_CACHED_OBJECTS: usize = 1_024;
const MAX_CACHED_BYTES: usize = 8 * 1024 * 1024;
/// Total verified scan ceiling aligned with `SpoolLimits::default()` to block unbounded DoS scans.
const MAX_TOTAL_SCAN_OBJECTS: usize = 65_536;
const MAX_TOTAL_SCAN_BYTES: usize = 256 * 1024 * 1024;

/// Compact protected context and the verified graphs retained for the returned summary window,
/// paired with explicit total/omission/pagination metadata.
#[derive(Default)]
pub(crate) struct CapturedLearningInventory {
    pub(crate) briefs: Vec<OrientLearningBrief>,
    pub(crate) objects: BTreeMap<ContentDigest, Vec<u8>>,
    /// Total verified captures admitted for this session before bounded summary windowing.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) total_captured_count: usize,
    /// Number of verified captures omitted from `briefs` due to the bounded summary window.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) omitted_count: usize,
    /// Deterministic pagination cursor (`proposal_id`) when `omitted_count > 0`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) next_cursor: Option<String>,
}

/// One deterministically paginated slice of verified captured-learning briefs for a session.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Default)]
pub(crate) struct CapturedLearningPage {
    pub(crate) briefs: Vec<OrientLearningBrief>,
    pub(crate) objects: BTreeMap<ContentDigest, Vec<u8>>,
    pub(crate) total_captured_count: usize,
    pub(crate) omitted_count: usize,
    pub(crate) next_cursor: Option<String>,
    pub(crate) has_more: bool,
}

#[derive(Default)]
struct ScanBudget {
    cache: BTreeMap<ContentDigest, Vec<u8>>,
    cached_bytes: usize,
    total_reads: usize,
    total_bytes: usize,
}

impl ScanBudget {
    fn read_object(
        &mut self,
        directory: &Path,
        digest: ContentDigest,
    ) -> Result<Vec<u8>, DeploymentSessionError> {
        if let Some(bytes) = self.cache.get(&digest) {
            return Ok(bytes.clone());
        }
        if self.total_reads >= MAX_TOTAL_SCAN_OBJECTS || self.total_bytes >= MAX_TOTAL_SCAN_BYTES {
            return Err(invalid(
                "complete captured-learning discovery exceeds its object or byte bound",
            ));
        }
        let remaining = MAX_TOTAL_SCAN_BYTES - self.total_bytes;
        let bytes =
            fss_publication::read_verified(directory, digest, MAX_RECORD_BYTES.min(remaining))
                .map_err(|_| invalid("captured-learning custody is unavailable or corrupt"))?;
        self.total_reads = self.total_reads.saturating_add(1);
        self.total_bytes = self
            .total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| invalid("captured-learning byte accounting overflow"))?;
        if self.total_bytes > MAX_TOTAL_SCAN_BYTES {
            return Err(invalid(
                "complete captured-learning discovery exceeds its byte bound",
            ));
        }
        if self.cache.len() < MAX_CACHED_OBJECTS
            && self.cached_bytes.saturating_add(bytes.len()) <= MAX_CACHED_BYTES
        {
            self.cached_bytes = self.cached_bytes.saturating_add(bytes.len());
            self.cache.insert(digest, bytes.clone());
        }
        Ok(bytes)
    }
}

struct VerifiedEntry {
    created_at_ns: i128,
    brief: OrientLearningBrief,
    manifest_root: ContentDigest,
    manifest_bytes: Vec<u8>,
    objects: BTreeMap<ContentDigest, Vec<u8>>,
}

/// Read-only preflight check of `agent/publications` before mutating session or publication
/// custody on disk.
///
/// If `agent/publications` does not exist yet (a fresh deployment), preflight succeeds without
/// creating anything. If it exists, it must satisfy the exact same layout, lock-freeness,
/// integrity, and learning-root structural bounds that [`captured_inventory`] enforces after
/// open, so refused opens leave `agent/` untouched.
pub(crate) fn preflight_publication_inventory(
    root: &Path,
    has_existing_sessions: bool,
) -> Result<(), DeploymentSessionError> {
    let directory = root.join(PUBLICATIONS_RELPATH);
    let metadata = match std::fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err(invalid(
                "captured-learning publication inventory is unavailable",
            ));
        }
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid(
            "captured-learning publication inventory has an invalid layout",
        ));
    }
    let inspection = fss_publication::inspect(&directory, publication_limits())?;
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
    let mut scan = ScanBudget::default();
    for visible in inspection.visible_roots() {
        if !visible.slot.as_str().starts_with("learning-") {
            continue;
        }
        if !has_existing_sessions {
            return Err(invalid(
                "captured-learning source closure or historical ownership failed verification",
            ));
        }
        let manifest_bytes = scan.read_object(&directory, visible.root)?;
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
        let metadata_digest = manifest
            .metadata_digest()
            .ok_or_else(|| invalid("captured-learning metadata is missing"))?;
        let mut objects = BTreeMap::new();
        for digest in manifest.children() {
            let bytes = scan.read_object(&directory, *digest)?;
            objects.insert(*digest, bytes);
        }
        let experience = decode_experience(
            objects
                .get(&metadata_digest)
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
    }
    Ok(())
}

fn collect_verified_entries(
    root: &Path,
    store: &dyn SessionProjection,
    session: &AgentSession,
    now: TimestampNs,
) -> Result<Vec<VerifiedEntry>, DeploymentSessionError> {
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
    let mut verified_entries = Vec::new();
    let mut seen_proposals = BTreeSet::new();
    let mut scan = ScanBudget::default();
    for visible in inspection.visible_roots() {
        if !visible.slot.as_str().starts_with("learning-") {
            continue;
        }
        let manifest_bytes = scan.read_object(&directory, visible.root)?;
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
            let bytes = scan.read_object(&directory, *digest)?;
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
        if !seen_proposals.insert(verified.proposal.proposal_id.clone()) {
            return Err(invalid(
                "captured-learning inventory contains a duplicate immutable proposal",
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
        let brief = OrientLearningBrief {
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
        };
        verified_entries.push(VerifiedEntry {
            created_at_ns: experience.created_at_ns,
            brief,
            manifest_root: visible.root,
            manifest_bytes,
            objects,
        });
    }
    Ok(verified_entries)
}

/// The session journal owner excludes cooperating writers. Current read/privacy admission is
/// evaluated first; historical grant membership alone never authorizes these private records.
///
/// When a session owns more than [`CAPTURED_LEARNING_SUMMARY_LIMIT`] verified captures, returns
/// the deterministic top-N most recent summary window alongside exact `total_captured_count`,
/// `omitted_count`, and pagination cursor metadata instead of refusing with a store error.
pub(crate) fn captured_inventory(
    root: &Path,
    store: &dyn SessionProjection,
    session: &AgentSession,
    now: TimestampNs,
) -> Result<CapturedLearningInventory, DeploymentSessionError> {
    let mut entries = collect_verified_entries(root, store, session, now)?;
    let total_captured_count = entries.len();
    if total_captured_count > CAPTURED_LEARNING_SUMMARY_LIMIT {
        // Select the top-N most recent captures deterministically (newest timestamp first,
        // tie-broken by ascending proposal_id).
        entries.sort_by(|left, right| {
            right
                .created_at_ns
                .cmp(&left.created_at_ns)
                .then_with(|| left.brief.proposal_id.cmp(&right.brief.proposal_id))
        });
        entries.truncate(CAPTURED_LEARNING_SUMMARY_LIMIT);
    }
    // Canonical ascending proposal_id ordering for orientation projection compatibility.
    entries.sort_by(|left, right| left.brief.proposal_id.cmp(&right.brief.proposal_id));

    let omitted_count = total_captured_count.saturating_sub(entries.len());
    let next_cursor = if omitted_count > 0 {
        entries.last().map(|entry| entry.brief.proposal_id.clone())
    } else {
        None
    };

    let mut result = CapturedLearningInventory {
        briefs: Vec::with_capacity(entries.len()),
        objects: BTreeMap::new(),
        total_captured_count,
        omitted_count,
        next_cursor,
    };
    for entry in entries {
        result.briefs.push(entry.brief);
        result.objects.extend(entry.objects);
        result
            .objects
            .insert(entry.manifest_root, entry.manifest_bytes);
    }
    Ok(result)
}

/// Deterministically paginates all verified captured-learning proposals belonging to `session`
/// in ascending `proposal_id` order starting strictly after `cursor`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn captured_inventory_page(
    root: &Path,
    store: &dyn SessionProjection,
    session: &AgentSession,
    now: TimestampNs,
    cursor: Option<&str>,
    limit: usize,
) -> Result<CapturedLearningPage, DeploymentSessionError> {
    let mut entries = collect_verified_entries(root, store, session, now)?;
    entries.sort_by(|left, right| left.brief.proposal_id.cmp(&right.brief.proposal_id));
    let total_captured_count = entries.len();

    let mut page_entries = Vec::with_capacity(limit.min(total_captured_count));
    let mut has_more = false;
    for entry in entries {
        if let Some(after) = cursor
            && entry.brief.proposal_id.as_str() <= after
        {
            continue;
        }
        if limit == 0 || page_entries.len() == limit {
            has_more = true;
            break;
        }
        page_entries.push(entry);
    }

    let omitted_count = total_captured_count.saturating_sub(page_entries.len());
    let next_cursor = if has_more {
        page_entries
            .last()
            .map(|entry| entry.brief.proposal_id.clone())
    } else {
        None
    };
    let mut page = CapturedLearningPage {
        briefs: Vec::with_capacity(page_entries.len()),
        objects: BTreeMap::new(),
        total_captured_count,
        omitted_count,
        next_cursor,
        has_more,
    };
    for entry in page_entries {
        page.briefs.push(entry.brief);
        page.objects.extend(entry.objects);
        page.objects
            .insert(entry.manifest_root, entry.manifest_bytes);
    }
    Ok(page)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_orient::{DeploymentHistory, OrientLimits};
    use crate::deployment_session::episode::{CloseRequest, close_plan};
    use crate::deployment_session::feedback::{FeedbackRequest, FeedbackTarget, publish_feedback};
    use crate::deployment_session::plan::{AlertRoute, PlanRecord, publish_plan};
    use crate::deployment_session::{
        OpenSessionRequest, SessionJournal, open_session, session_position,
    };
    use crate::webhook::WebhookDisclosureProfile;
    use crate::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};
    use fss_core::{
        AgentView, BudgetVector, CanonicalEncode, ContextAuthority, FeedbackProposalKind,
        OperationId, PrincipalId, RequestedDisposition, RootAuthoritySpec,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    static INV_TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn single_session_64_captured_learning_proposals_paginate_and_detect_tamper()
    -> Result<(), Box<dyn std::error::Error>> {
        let seq = INV_TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("fss-learning-inv-64-{}-{seq}", std::process::id()));
        let scratch = std::env::temp_dir().join(format!(
            "fss-learning-inv-64-cx-{}-{seq}",
            std::process::id()
        ));
        for p in [&root, &scratch] {
            if p.exists() {
                std::fs::remove_dir_all(p)?;
            }
        }
        let spec = RootAuthoritySpec {
            trace_id: format!("trace:inv-64-{seq}"),
            operation_id: OperationId::parse(format!("operation:inv-64-{seq}"))?,
            principal: format!("operator:inv-64-{seq}"),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::default(),
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"inv-64"),
            generation: 1,
        };
        let authority = ContextAuthority::new_root(spec)?;
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority,
            scratch.clone(),
        )?);
        let site = "site:learning-inv-64";
        drop(ReferenceDeployment::open(&root, site, &cx)?);

        let principal = PrincipalId::parse("principal:inv-64-operator")?;
        let opened = open_session(
            &root,
            &OpenSessionRequest {
                mission: "Single-session 64 captured learning proposals".into(),
                objective: "Verify bounded summary and pagination without StoreInvalid.".into(),
                principal: principal.clone(),
                view: AgentView::EpistemicMap,
                token_budget: 64_000,
            },
        )?;
        let approval = ContentDigest::sha256(b"inv-64-approval");
        let plan = PlanRecord {
            plan_id: PlanRecord::identity(
                &opened.session.session_id,
                &opened.orientation.anchor_token,
                approval,
            ),
            session_id: opened.session.session_id.clone(),
            mission_id: opened.session.mission_id.clone(),
            principal: principal.clone(),
            anchor_token: opened.orientation.anchor_token.clone(),
            intent: "alert".into(),
            event_id: "event:inv-64".into(),
            event_revision: ContentDigest::sha256(b"inv-64-rev"),
            route: AlertRoute {
                relay: "127.0.0.1:9".into(),
                path: "/fss/alert".into(),
                plaintext_approval: ContentDigest::sha256(b"inv-64-route"),
                deadline_ms: 5_000,
                disclosure_profile: WebhookDisclosureProfile::ReferencesV1,
                metadata_approval: None,
            },
            operation_id: "operation:inv-64-plan".into(),
            obligation_id: "obligation:inv-64-plan".into(),
            plan_approval: approval,
            control_plan_digest: ContentDigest::sha256(b"inv-64-plan-child"),
            case: None,
            created_at: TimestampNs(0),
        };
        publish_plan(&root, &plan, b"inv-64-plan-child")?;
        let owner = ReferenceDeployment::open(&root, site, &cx)?;
        let closed = close_plan(
            &root,
            &CloseRequest {
                session_id: opened.session.session_id.clone(),
                principal: principal.clone(),
                plan_id: plan.plan_id.clone(),
            },
            &|ep| format!("inv-64 episode {}", ep.episode_id),
        )?;
        drop(owner);

        // Publish one initial capture via public publish_feedback, then capture 63 additional
        // verified learning proposals directly on the SAME session (total 64 >> 16!).
        let limits = OrientLimits::default();
        let history = DeploymentHistory::read(&root, &limits)?;
        let head = history.snapshot_at(history.head())?;
        let now = TimestampNs(0);

        let mut all_ids = BTreeSet::new();
        for idx in 0..64_usize {
            let req = FeedbackRequest {
                session_id: opened.session.session_id.clone(),
                principal: principal.clone(),
                target: FeedbackTarget::Plan(plan.plan_id.clone()),
                kind: FeedbackProposalKind::RunbookCandidate,
                statement: format!("Single-session proposal {idx:03}; advisory only."),
                supporting: vec![closed.episode.root],
                contradicting: Vec::new(),
                disposition: RequestedDisposition::CreateLearningProposal,
            };
            if idx == 0 {
                let pub0 = publish_feedback(&root, &req)?;
                let l0 = pub0.learning.ok_or("first capture missing")?;
                all_ids.insert(l0.proposal.proposal_id);
                continue;
            }
            // Publish feedback root directly via RecordOnly-equivalent canonical proposal bytes,
            // then run real `super::capture` so every closure, binding, and digest is authentic.
            let mut journal = SessionJournal::open(&root)?;
            let position = session_position(
                &mut journal,
                &history,
                &principal,
                &opened.session.session_id,
                now,
            )?;
            let proposal = fss_core::AgentFeedbackProposal::new(
                format!("feedback:inv64-{idx:04}"),
                principal.clone(),
                opened.session.session_id.clone(),
                opened.session.current_anchor.clone(),
                crate::deployment_session::feedback::target_json(&req.target),
                req.kind,
                req.statement.clone(),
                vec![closed.episode.root.to_text()],
                Vec::new(),
                RequestedDisposition::CreateLearningProposal,
                fss_core::FeedbackPrivacyClass::Private,
                i128::try_from(idx).unwrap_or(0),
            )?;
            let fb_slot = fss_publication::SlotName::parse(&format!(
                "feedback-{}",
                hex(ContentDigest::sha256(proposal.feedback_id.as_bytes()))
            ))?;
            let fb_bytes = proposal.try_canonical_bytes()?;
            let fb_json = crate::deployment_session::feedback::render_json(&proposal).into_bytes();
            let fb_receipt = crate::deployment_session::publish_record(
                &root,
                &fb_slot,
                "agent-feedback",
                &fb_bytes,
                &[fb_json],
                None,
            )?;
            let published_fb = crate::deployment_session::feedback::PublishedFeedback {
                proposal,
                root: fb_receipt.root,
                session: position.session.clone(),
                orientation: opened.orientation.clone(),
                request_digest: ContentDigest::sha256(format!("req-{idx}").as_bytes()),
                head_moved: false,
                learning: None,
                learning_refusal: None,
                case: None,
                case_refusal: None,
            };
            let captured = super::super::capture(
                &root,
                &req,
                &published_fb,
                &position,
                &history,
                &head,
                &mut journal.store,
                TimestampNs(1_000),
            )?;
            assert!(captured.committed);
            all_ids.insert(captured.proposal.proposal_id);
        }
        assert_eq!(all_ids.len(), 64);

        // Preflight succeeds across all 64 learning roots.
        preflight_publication_inventory(&root, true)?;

        // captured_inventory MUST NOT fail with StoreInvalid when 64 > 16!
        let journal = SessionJournal::open(&root)?;
        let inv = captured_inventory(&root, &journal.store, &opened.session, TimestampNs(1_000))?;
        assert_eq!(inv.total_captured_count, 64);
        assert_eq!(inv.briefs.len(), CAPTURED_LEARNING_SUMMARY_LIMIT);
        assert_eq!(inv.omitted_count, 64 - CAPTURED_LEARNING_SUMMARY_LIMIT);
        assert!(inv.next_cursor.is_some());

        // Paginate across ALL 64 proposals deterministically with page size 10.
        let mut paginated = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = captured_inventory_page(
                &root,
                &journal.store,
                &opened.session,
                TimestampNs(1_000),
                cursor.as_deref(),
                10,
            )?;
            assert_eq!(page.total_captured_count, 64);
            assert_eq!(page.omitted_count, 64 - page.briefs.len());
            for b in &page.briefs {
                paginated.push(b.proposal_id.clone());
            }
            if !page.has_more {
                assert!(page.next_cursor.is_none());
                break;
            }
            cursor = page.next_cursor;
        }
        assert_eq!(paginated.len(), 64);
        assert!(paginated.windows(2).all(|w| w[0] < w[1]));
        let paginated_set: BTreeSet<_> = paginated.into_iter().collect();
        assert_eq!(paginated_set, all_ids);

        // Corrupt a learning root outside the top-16 window: captured_inventory MUST still fail closed!
        let roots_dir = root.join(PUBLICATIONS_RELPATH).join("roots");
        let victim = std::fs::read_dir(&roots_dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .find(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("learning-"))
            })
            .ok_or("learning root missing")?;
        std::fs::write(&victim, b"tampered-learning-root")?;
        let err = captured_inventory(&root, &journal.store, &opened.session, TimestampNs(1_000));
        assert!(matches!(err, Err(DeploymentSessionError::StoreInvalid(_))));

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&scratch);
        Ok(())
    }
}
