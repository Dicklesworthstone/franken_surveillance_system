#![forbid(unsafe_code)]
//! Exact opening retries reuse immutable history without reopening live authority.

use super::*;

/// Returns a completed opening, or leaves a genuinely new/incomplete opening to the original
/// digest-checked open path. The caller keeps this same journal locked through either path.
#[allow(clippy::too_many_arguments)]
pub(super) fn resume_if_present(
    root: &Path,
    journal: &mut SessionJournal,
    snapshot: &DeploymentSnapshot,
    request: &OpenSessionRequest,
    expected_mission: &MissionRecord,
    request_digest: ContentDigest,
    limits: &OrientLimits,
) -> Result<Option<OpenedSession>, DeploymentSessionError> {
    let now = evidence_now(snapshot);
    let existing = journal.store.opening_workspace_for_retry(
        &request.principal,
        &expected_mission.session_id,
        now,
    );
    // Reads may persist clock or expiry transitions even when their result is a refusal.
    journal.commit_pin()?;
    let Some(existing) = existing? else {
        return Ok(None);
    };
    let (session, opening) = existing.result;
    if session.mission_id != expected_mission.mission_id
        || session.session_id != expected_mission.session_id
        || session.principal_id != request.principal
        || session.view != request.view
        || session.token_budget != request.token_budget
        || session.current_anchor != snapshot.anchor
    {
        return Err(DeploymentSessionError::SessionStale(
            "the live session no longer matches its opening request; resume its current workspace"
                .to_owned(),
        ));
    }
    if opening.is_none() {
        // Admit the original private opening footprint before reading retained mission prose
        // or recomposing memory. A partially opened session must not restore narrowed grants.
        let original_capabilities: BTreeSet<_> = SESSION_CAPABILITIES
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect();
        if session.capabilities != original_capabilities
            || session.privacy_scope != BTreeSet::from([SESSION_PRIVACY_SCOPE.to_owned()])
        {
            return Err(DeploymentSessionError::SessionStale(
                "an incomplete opening no longer has its original authority projection".to_owned(),
            ));
        }
    }
    let digest = match &opening {
        Some(revision) => {
            ContentDigest::parse(&revision.capsule().objective_digest).map_err(|_| {
                DeploymentSessionError::StoreInvalid(
                    "the opening workspace has an invalid mission identity".to_owned(),
                )
            })?
        }
        None => expected_mission.digest(),
    };
    let published = read_published(root, &MissionRecord::slot(digest)?)
        .map_err(|error| match error {
            DeploymentSessionError::HandoffInvalid(reason) => {
                DeploymentSessionError::StoreInvalid(reason)
            }
            other => other,
        })?
        .ok_or_else(|| {
            DeploymentSessionError::StoreInvalid(
                "the retained opening mission is missing".to_owned(),
            )
        })?;
    if ContentDigest::sha256(&published.record) != digest {
        return Err(DeploymentSessionError::StoreInvalid(
            "the retained opening mission does not match its workspace".to_owned(),
        ));
    }
    let mission = MissionRecord::from_bytes(&published.record).map_err(|_| {
        DeploymentSessionError::StoreInvalid(
            "the retained opening mission is not canonical".to_owned(),
        )
    })?;
    if &mission != expected_mission {
        return Err(DeploymentSessionError::SessionStale(
            "the requested opening differs from the immutable retained mission".to_owned(),
        ));
    }
    let Some(revision) = opening else {
        // The unchanged store.open below checks the persisted original opening digest;
        // changed advisory state refuses instead of inventing a lost first frame.
        return Ok(None);
    };
    let orientation = orient_bound(
        Some((root, snapshot)),
        snapshot,
        session.view,
        &request.principal,
        &session.mission_id,
        &session.session_id,
        limits,
        session_briefs(root, &journal.store, &session, &snapshot.anchor, now)?,
    )?;
    if revision.contract_basis() != &orientation.capsule().contract_basis {
        return Err(DeploymentSessionError::SessionStale(
            "the opening contract basis changed; explicit resume or rebase is required".to_owned(),
        ));
    }
    Ok(Some(OpenedSession {
        session,
        mission,
        mission_root: published.root,
        revision,
        orientation,
        journal_root: journal.store.committed_root(),
        request_digest,
    }))
}
