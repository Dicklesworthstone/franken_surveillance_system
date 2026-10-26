#![forbid(unsafe_code)]
//! Exact opening retries recover immutable history without reopening live authority.

use std::collections::BTreeSet;
use std::error::Error;

use super::*;
use crate::agent_session::{ReferenceSessionError, SessionRefresh};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn opening_retry_returns_original_revision_and_preserves_current_state_without_charge() -> TestResult
{
    let (mut store, session, request) = tests::fixture()?;
    let first = store.publish_workspace(&session.principal_id, request, TimestampNs(20))?;
    let second = store.publish_workspace(
        &session.principal_id,
        tests::successor(&first.result),
        TimestampNs(21),
    )?;
    let current = store.rotate_symbols(
        &session.principal_id,
        &session.session_id,
        0,
        TimestampNs(21),
    )?;
    let before_budget = store.remaining_token_budget(
        &session.principal_id,
        &session.session_id,
        TimestampNs(21),
    )?;
    let root = store.committed_root();
    let mut store = tests::reopen(store)?;
    let recovered = store
        .opening_workspace_for_retry(&session.principal_id, &session.session_id, TimestampNs(21))?
        .ok_or("existing opening")?;
    assert_eq!(recovered.result.0, current);
    assert_eq!(recovered.result.1, Some(first.result));
    assert_eq!(store.committed_root(), root);
    assert_eq!(
        store.remaining_token_budget(
            &session.principal_id,
            &session.session_id,
            TimestampNs(21)
        )?,
        before_budget
    );
    assert_eq!(
        store
            .workspace_head(&session.principal_id, &session.session_id, TimestampNs(21))?
            .result
            .revision,
        second.result
    );
    Ok(())
}

#[test]
fn only_never_recorded_identity_is_absent_and_interrupted_open_stays_authenticated() -> TestResult {
    let (mut store, session, _) = tests::fixture()?;
    let absent = SessionId::parse("session:never-recorded")?;
    let root = store.committed_root();
    assert!(
        store
            .opening_workspace_for_retry(&session.principal_id, &absent, TimestampNs(20))?
            .is_none()
    );
    assert_eq!(store.committed_root(), root);
    let interrupted = store
        .opening_workspace_for_retry(&session.principal_id, &session.session_id, TimestampNs(20))?
        .ok_or("retained interrupted opening")?;
    assert_eq!(interrupted.result.0, session);
    assert!(interrupted.result.1.is_none());
    let mut store = tests::reopen(store)?;
    let interrupted = store
        .opening_workspace_for_retry(&session.principal_id, &session.session_id, TimestampNs(20))?
        .ok_or("recovered interrupted opening")?;
    assert_eq!(interrupted.result.0, session);
    assert!(interrupted.result.1.is_none());
    let foreign = PrincipalId::parse("principal:foreign")?;
    assert!(matches!(
        store.opening_workspace_for_retry(&foreign, &session.session_id, TimestampNs(20)),
        Err(DurableWorkspaceError::Refused(WorkspaceError::Session(
            ReferenceSessionError::Unavailable
        )))
    ));
    store.close(&session.principal_id, &session.session_id, TimestampNs(21))?;
    let mut store = tests::reopen(store)?;
    assert!(matches!(
        store.opening_workspace_for_retry(
            &session.principal_id,
            &session.session_id,
            TimestampNs(21)
        ),
        Err(DurableWorkspaceError::Refused(WorkspaceError::Session(
            ReferenceSessionError::Unavailable
        )))
    ));
    Ok(())
}

#[test]
fn foreign_and_narrowed_sessions_cannot_recover_the_old_opening_projection() -> TestResult {
    let (mut store, session, request) = tests::fixture()?;
    store.publish_workspace(&session.principal_id, request, TimestampNs(20))?;
    let foreign = PrincipalId::parse("principal:foreign")?;
    assert!(matches!(
        store.opening_workspace_for_retry(&foreign, &session.session_id, TimestampNs(21)),
        Err(DurableWorkspaceError::Refused(WorkspaceError::Session(
            ReferenceSessionError::Unavailable
        )))
    ));
    let narrowed = store.refresh(
        &session.principal_id,
        &session.session_id,
        SessionRefresh {
            expected_session_digest: session.session_digest(),
            current_anchor: session.current_anchor,
            capabilities: BTreeSet::new(),
            privacy_scope: session.privacy_scope,
        },
        TimestampNs(22),
    )?;
    let mut store = tests::reopen(store)?;
    assert!(matches!(
        store.opening_workspace_for_retry(
            &narrowed.principal_id,
            &narrowed.session_id,
            TimestampNs(22)
        ),
        Err(DurableWorkspaceError::Refused(WorkspaceError::Unavailable))
    ));
    Ok(())
}

#[test]
fn closed_and_expired_sessions_never_become_fresh_open_requests_after_restart() -> TestResult {
    let (mut store, session, request) = tests::fixture()?;
    store.publish_workspace(&session.principal_id, request, TimestampNs(20))?;
    store.close(&session.principal_id, &session.session_id, TimestampNs(21))?;
    let mut store = tests::reopen(store)?;
    assert!(matches!(
        store.opening_workspace_for_retry(
            &session.principal_id,
            &session.session_id,
            TimestampNs(21)
        ),
        Err(DurableWorkspaceError::Refused(WorkspaceError::Session(
            ReferenceSessionError::Unavailable
        )))
    ));

    let (mut store, session, request) = tests::fixture()?;
    store.publish_workspace(&session.principal_id, request, TimestampNs(20))?;
    let root = store.committed_root();
    assert!(matches!(
        store.opening_workspace_for_retry(
            &session.principal_id,
            &session.session_id,
            TimestampNs(1000)
        ),
        Err(DurableWorkspaceError::Refused(WorkspaceError::Session(
            ReferenceSessionError::Unavailable
        )))
    ));
    assert_ne!(
        store.committed_root(),
        root,
        "expiry tombstone must be durable before refusal"
    );
    let mut store = tests::reopen(store)?;
    assert!(matches!(
        store.opening_workspace_for_retry(
            &session.principal_id,
            &session.session_id,
            TimestampNs(20)
        ),
        Err(DurableWorkspaceError::Refused(WorkspaceError::Session(
            ReferenceSessionError::Unavailable
        )))
    ));
    Ok(())
}
