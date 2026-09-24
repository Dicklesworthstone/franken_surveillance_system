#![forbid(unsafe_code)]

use super::*;
use crate::agent_session::workspace::checkpoint::{
    MAX_WORKSPACE_CHECKPOINT_BYTES, WORKSPACE_CHECKPOINT_FORMAT, WorkspaceCheckpointError,
};

fn restore(
    bytes: &[u8],
    digest: ContentDigest,
) -> Result<ReferenceWorkspaceStore, WorkspaceCheckpointError> {
    ReferenceWorkspaceStore::restore_checkpoint(
        bytes,
        digest,
        WorkspaceLimits::default(),
        MAX_WORKSPACE_CHECKPOINT_BYTES,
    )
}

#[test]
fn checkpoint_roundtrip_preserves_heads_history_charges_and_retries() -> TestResult {
    let mut f = Fixture::new()?;
    let initial = f.initial();
    let first = f.write(initial.clone())?;
    let second_request = f.append(&first);
    let second = f.write(second_request.clone())?;
    let checkpoint = f.workspaces.checkpoint(MAX_WORKSPACE_CHECKPOINT_BYTES)?;
    let retained = f.workspaces.retained_bytes();
    f.workspaces = restore(checkpoint.as_bytes(), checkpoint.digest())?;
    assert_eq!(f.workspaces.retained_bytes(), retained);
    assert_eq!(
        f.workspaces.checkpoint(MAX_WORKSPACE_CHECKPOINT_BYTES)?,
        checkpoint
    );
    assert_eq!(f.write(initial)?, first);
    assert_eq!(f.write(second_request)?, second);
    let resumed = f.workspaces.resume(
        &mut f.sessions,
        &f.principal,
        &f.capsule.session_id,
        first.digest(),
        TimestampNs(20),
    )?;
    assert!(resumed.superseded);
    assert_eq!(resumed.head_digest, second.digest());
    let third = f.write(f.append(&second))?;
    assert_eq!(third.parent_digest(), Some(second.digest()));
    Ok(())
}

#[test]
fn recovery_retains_rebase_debt_obligations_and_invalidated_actions() -> TestResult {
    let mut f = Fixture::new()?;
    let first = f.write(f.initial())?;
    let anchor = f.move_anchor()?;
    let mut request = f.append(&first);
    request.mode = WorkspaceWriteMode::Rebase;
    request.capsule.current_anchor = anchor;
    request.capsule.situation_capsule_digest = "situation:0002".to_owned();
    request.capsule.decision_digest = "decision:0002".to_owned();
    request
        .capsule
        .epistemic_debt
        .extend(first.capsule.assumptions.clone());
    request.capsule.next_actions.clear();
    let rebased = f.write(request)?;
    let checkpoint = f.workspaces.checkpoint(MAX_WORKSPACE_CHECKPOINT_BYTES)?;
    f.workspaces = restore(checkpoint.as_bytes(), checkpoint.digest())?;
    let resumed = f.workspaces.resume(
        &mut f.sessions,
        &f.principal,
        &f.capsule.session_id,
        rebased.digest(),
        TimestampNs(20),
    )?;
    assert_eq!(resumed.revision, rebased);
    assert_eq!(
        resumed.revision.invalidated_actions(),
        first.capsule.next_actions.as_slice()
    );
    assert!(!resumed.rebase_required);
    assert_eq!(
        resumed.revision.capsule().open_obligations,
        first.capsule.open_obligations
    );
    Ok(())
}

#[test]
fn every_truncated_prefix_and_bit_flip_fails_the_pinned_root() -> TestResult {
    let mut f = Fixture::new()?;
    f.write(f.initial())?;
    let checkpoint = f.workspaces.checkpoint(MAX_WORKSPACE_CHECKPOINT_BYTES)?;
    for end in 0..checkpoint.as_bytes().len() {
        assert!(matches!(
            restore(&checkpoint.as_bytes()[..end], checkpoint.digest()),
            Err(WorkspaceCheckpointError::IntegrityMismatch)
        ));
    }
    let mut corrupt = checkpoint.as_bytes().to_vec();
    for index in 0..corrupt.len() {
        corrupt[index] ^= 1;
        assert!(matches!(
            restore(&corrupt, checkpoint.digest()),
            Err(WorkspaceCheckpointError::IntegrityMismatch)
        ));
        corrupt[index] ^= 1;
    }
    Ok(())
}

#[test]
fn a_valid_old_snapshot_does_not_satisfy_the_latest_pin() -> TestResult {
    let mut f = Fixture::new()?;
    let first = f.write(f.initial())?;
    let old = f.workspaces.checkpoint(MAX_WORKSPACE_CHECKPOINT_BYTES)?;
    f.write(f.append(&first))?;
    let current = f.workspaces.checkpoint(MAX_WORKSPACE_CHECKPOINT_BYTES)?;
    assert!(matches!(
        restore(old.as_bytes(), current.digest()),
        Err(WorkspaceCheckpointError::IntegrityMismatch)
    ));
    Ok(())
}

#[test]
fn no_session_is_created_and_restored_grants_do_not_authorize_reads() -> TestResult {
    let mut f = Fixture::new()?;
    let first = f.write(f.initial())?;
    let checkpoint = f.workspaces.checkpoint(MAX_WORKSPACE_CHECKPOINT_BYTES)?;
    f.workspaces = restore(checkpoint.as_bytes(), checkpoint.digest())?;
    let mut empty_sessions = ReferenceSessionStore::default();
    assert!(matches!(
        f.workspaces.resume(
            &mut empty_sessions,
            &f.principal,
            &f.capsule.session_id,
            first.digest(),
            TimestampNs(20),
        ),
        Err(WorkspaceError::Session(_))
    ));
    f.sessions
        .close(&f.principal, &f.capsule.session_id, TimestampNs(20))?;
    assert!(matches!(
        f.workspaces.resume(
            &mut f.sessions,
            &f.principal,
            &f.capsule.session_id,
            first.digest(),
            TimestampNs(20),
        ),
        Err(WorkspaceError::Session(_))
    ));
    Ok(())
}

#[test]
fn restored_underdeclared_projection_still_requires_original_capabilities() -> TestResult {
    let mut f = Fixture::new()?;
    let mut request = f.initial();
    request.capsule.capability_projection.clear();
    let first = f.write(request)?;
    let checkpoint = f.workspaces.checkpoint(MAX_WORKSPACE_CHECKPOINT_BYTES)?;
    f.workspaces = restore(checkpoint.as_bytes(), checkpoint.digest())?;
    let session = f
        .sessions
        .session(&f.principal, &f.capsule.session_id, TimestampNs(20))?;
    f.sessions.refresh(
        &f.principal,
        &f.capsule.session_id,
        SessionRefresh {
            expected_session_digest: session.session_digest(),
            current_anchor: session.current_anchor.clone(),
            capabilities: BTreeSet::new(),
            privacy_scope: session.privacy_scope.clone(),
        },
        TimestampNs(20),
    )?;
    assert!(matches!(
        f.workspaces.resume(
            &mut f.sessions,
            &f.principal,
            &f.capsule.session_id,
            first.digest(),
            TimestampNs(20),
        ),
        Err(WorkspaceError::Unavailable)
    ));
    Ok(())
}

#[test]
fn runtime_ceilings_and_output_capacity_are_not_silently_widened() -> TestResult {
    let mut f = Fixture::new()?;
    f.write(f.initial())?;
    let checkpoint = f.workspaces.checkpoint(MAX_WORKSPACE_CHECKPOINT_BYTES)?;
    assert!(matches!(
        f.workspaces.checkpoint(checkpoint.as_bytes().len() - 1),
        Err(WorkspaceCheckpointError::CapacityExceeded)
    ));
    assert!(matches!(
        ReferenceWorkspaceStore::restore_checkpoint(
            checkpoint.as_bytes(),
            checkpoint.digest(),
            WorkspaceLimits {
                max_revisions_per_workspace: 1,
                ..WorkspaceLimits::default()
            },
            MAX_WORKSPACE_CHECKPOINT_BYTES,
        ),
        Err(WorkspaceCheckpointError::CapacityExceeded)
    ));
    assert!(matches!(
        ReferenceWorkspaceStore::restore_checkpoint(
            checkpoint.as_bytes(),
            checkpoint.digest(),
            WorkspaceLimits::default(),
            0,
        ),
        Err(WorkspaceCheckpointError::CapacityExceeded)
    ));
    Ok(())
}

#[test]
fn rehashed_trailing_bytes_and_unknown_format_are_rejected() -> TestResult {
    let mut f = Fixture::new()?;
    f.write(f.initial())?;
    let checkpoint = f.workspaces.checkpoint(MAX_WORKSPACE_CHECKPOINT_BYTES)?;
    let mut trailing = checkpoint.as_bytes().to_vec();
    trailing.push(0);
    assert!(restore(&trailing, ContentDigest::sha256(&trailing)).is_err());
    let mut output = CanonicalEncoder::new();
    output.text("fss.reference_workspace_checkpoint.v999");
    let unknown = output.finish_checked()?;
    assert!(matches!(
        restore(&unknown, ContentDigest::sha256(&unknown)),
        Err(WorkspaceCheckpointError::UnsupportedFormat)
    ));
    Ok(())
}

#[test]
fn oversized_count_is_rejected_before_record_allocation() -> TestResult {
    let mut output = CanonicalEncoder::new();
    output.text(WORKSPACE_CHECKPOINT_FORMAT);
    let limits = WorkspaceLimits::default();
    for limit in [
        limits.max_workspaces,
        limits.max_revisions_per_workspace,
        limits.max_revision_bytes,
        limits.max_history_bytes,
    ] {
        output.u64(limit as u64);
    }
    output.u64(u64::MAX);
    let bytes = output.finish_checked()?;
    assert!(matches!(
        restore(&bytes, ContentDigest::sha256(&bytes)),
        Err(WorkspaceCheckpointError::CapacityExceeded)
    ));
    Ok(())
}

// Model a corrupted writer/storage implementation, not an attacker choosing a trusted root.
// Rehashing a structurally invalid history must not make it pass transition validation.
#[test]
fn rehashed_invalid_revision_history_is_still_refused() -> TestResult {
    for mutation in 0..8 {
        let mut f = Fixture::new()?;
        let first = f.write(f.initial())?;
        f.write(f.append(&first))?;
        let history = f
            .workspaces
            .histories
            .get_mut(&f.capsule.session_id)
            .ok_or("missing test history")?;
        let second = history.last_mut().ok_or("missing test revision")?;
        match mutation {
            0 => second.parent = None,
            1 => second.capsule.revision = 3,
            2 => second.capsule.open_obligations.clear(),
            3 => second.capsule.session_id = SessionId::parse("session:other")?,
            4 => {
                second
                    .capability_scope
                    .insert("capability:forged".to_owned());
            }
            5 => second.privacy_scope.clear(),
            6 => second
                .invalidated_actions
                .push("action:invented".to_owned()),
            _ => second.capsule.unknowns.clear(),
        }
        second.bytes = encode_revision(second)?;
        second.digest = ContentDigest::sha256(&second.bytes);
        let checkpoint = f.workspaces.checkpoint(MAX_WORKSPACE_CHECKPOINT_BYTES)?;
        assert!(restore(checkpoint.as_bytes(), checkpoint.digest()).is_err());
    }
    Ok(())
}

#[test]
fn duplicate_missing_and_reordered_revisions_are_not_repaired_implicitly() -> TestResult {
    for mutation in 0..3 {
        let mut f = Fixture::new()?;
        let first = f.write(f.initial())?;
        f.write(f.append(&first))?;
        let history = f
            .workspaces
            .histories
            .get_mut(&f.capsule.session_id)
            .ok_or("missing test history")?;
        match mutation {
            0 => history.insert(1, first),
            1 => {
                history.remove(0);
            }
            _ => history.reverse(),
        }
        let checkpoint = f.workspaces.checkpoint(MAX_WORKSPACE_CHECKPOINT_BYTES)?;
        assert!(restore(checkpoint.as_bytes(), checkpoint.digest()).is_err());
    }
    Ok(())
}

#[test]
fn independent_replay_has_identical_checkpoint_bytes() -> TestResult {
    let mut left = Fixture::new()?;
    let mut right = Fixture::new()?;
    let a = left.write(left.initial())?;
    let b = right.write(right.initial())?;
    left.write(left.append(&a))?;
    right.write(right.append(&b))?;
    assert_eq!(
        left.workspaces.checkpoint(MAX_WORKSPACE_CHECKPOINT_BYTES)?,
        right
            .workspaces
            .checkpoint(MAX_WORKSPACE_CHECKPOINT_BYTES)?
    );
    Ok(())
}
