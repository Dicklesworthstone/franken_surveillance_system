#![forbid(unsafe_code)]
//! Actual source disclosure and workspace state share one exclusive journal owner.

use fss_core::{SessionCapsule, SessionCapsuleParams};
use fss_reference::agent_session::checkpoint::journal::{DurableSessionError, DurableSessionStore};
use fss_reference::agent_session::checkpoint::journal::workspace::DurableWorkspaceError;
use fss_reference::agent_session::workspace::{WorkspaceError, WorkspaceLimits, WorkspaceRevision,
    WorkspaceWrite, WorkspaceWriteMode};

use super::*;

fn initial_workspace(f: &Fixture) -> TestResult<WorkspaceWrite> {
    let fingerprint = f.publication.publication.situation.capsule.decision_fingerprint()?;
    let capsule = SessionCapsule::new(SessionCapsuleParams {
        session_id: f.session.session_id.clone(), revision: 0,
        principal: f.session.principal_id.as_str().to_owned(),
        capability_projection: f.session.capabilities.iter().cloned().collect(),
        objective_digest: ContentDigest::sha256(b"investigate retained reference source").to_string(),
        base_anchor: f.session.current_anchor.clone(), current_anchor: f.session.current_anchor.clone(),
        situation_capsule_digest: fingerprint.to_string(), decision_digest: fingerprint.to_string(),
        active_hypotheses: vec!["hypothesis:unconfirmed-presence".to_owned()],
        assumptions: vec!["assumption:coverage".to_owned()],
        unknowns: vec!["unknown:classification".to_owned()],
        not_observable_domains: vec!["domain:independent-corroboration".to_owned()],
        epistemic_debt: vec!["debt:corroboration".to_owned()],
        // Reference cognition, not an asserted terminal outcome of a real external effect.
        open_obligations: vec!["obligation:inspect-retained-source".to_owned()],
        budget_ledger: BudgetVector::builder().tokens(5_000).bytes(1024).build()?,
        bookmarked_evidence: vec![f.descriptor.subject_digest],
        next_actions: vec!["action:inspect-source".to_owned()],
    })?;
    Ok(WorkspaceWrite { expected_head: None, capsule, mode: WorkspaceWriteMode::Advance })
}

fn advance_workspace(previous: &WorkspaceRevision) -> WorkspaceWrite {
    let mut capsule = previous.capsule().clone(); capsule.revision += 1;
    WorkspaceWrite { expected_head: Some(previous.digest()), capsule, mode: WorkspaceWriteMode::Advance }
}

fn rebase_request(session: &AgentSession, previous: &WorkspaceRevision) -> (SessionRefresh, WorkspaceWrite) {
    let mut write = advance_workspace(previous); write.mode = WorkspaceWriteMode::Rebase;
    write.capsule.current_anchor.commit_sequence += 1;
    // This is a runtime-supplied synthetic successor, not a source-custody assertion.
    write.capsule.current_anchor.state_root = ContentDigest::sha256(b"fixture:successor-authority");
    write.capsule.situation_capsule_digest = ContentDigest::sha256(b"fixture:rebased-situation").to_string();
    write.capsule.decision_digest = ContentDigest::sha256(b"fixture:rebased-decision").to_string();
    write.capsule.epistemic_debt.extend(write.capsule.assumptions.clone());
    write.capsule.assumptions.clear(); write.capsule.next_actions.clear();
    let refresh = SessionRefresh {
        expected_session_digest: session.session_digest(), current_anchor: write.capsule.current_anchor.clone(),
        capabilities: session.capabilities.clone(), privacy_scope: session.privacy_scope.clone(),
    };
    (refresh, write)
}

fn cursor_consumed(f: &Fixture, owner: &DurableDisclosureStore) -> TestResult<bool> {
    let cursor = &f.read.continuation.as_ref().ok_or("missing source continuation")?.cursor_digest;
    Ok(owner.catalog().issued_cursor(cursor).ok_or("lost source continuation")?.consumed)
}

#[test]
fn workspace_and_real_source_admissions_recover_under_one_root() -> TestResult {
    let (mut f, mut owner) = Fixture::new()?;
    owner.initialize_workspaces(WorkspaceLimits::default())?;
    let first = owner.publish_workspace(&f.session.principal_id, initial_workspace(&f)?, TimestampNs(1_000))?;
    f.advance(&mut owner)?;
    let second = owner.publish_workspace(&f.session.principal_id, advance_workspace(&first.result), TimestampNs(1_001))?;
    let root = owner.committed_root(); drop(owner);
    let mut owner = DurableDisclosureStore::open_existing(f.path(), root, f.limits, f.blueprint.clone())?;
    let resumed = owner.resume_workspace(&f.session.principal_id, &f.session.session_id, second.result.digest(), TimestampNs(1_001))?;
    assert_eq!(resumed.result.revision, second.result);
    assert_eq!(resumed.committed_root, root);
    assert!(!cursor_consumed(&f, &owner)?);
    assert_eq!(owner.remaining_token_budget(&f.session.principal_id, &f.session.session_id, TimestampNs(1_001))?, 4_488);
    let source = owner.hydrate_context_slot_from_source(&f.session.principal_id, &f.publication,
        &f.read, &f.custody, TimestampNs(1_002))?;
    let binding = owner.catalog().source_binding(&f.descriptor.handle_id, f.descriptor.descriptor_digest)
        .ok_or("missing source custody binding")?;
    source.response.verify_source_for(&f.publication, &f.session, binding)?;
    assert_eq!(source.response.response.artifact.as_ref().ok_or("missing source bytes")?.payload, f.source);
    let admitted_request = source.response.request.request_digest;
    let admission_root = source.committed_root;
    let receipt = source.response.response.receipt.receipt_digest;
    let mut write = advance_workspace(&second.result);
    write.capsule.bookmarked_evidence.push(receipt);
    // Even an unchanged declarative workspace budget cannot refund the actual session charge.
    let third = owner.publish_workspace(&f.session.principal_id, write, TimestampNs(1_002))?;
    let root = owner.committed_root(); drop(owner);
    let mut owner = DurableDisclosureStore::open_existing(f.path(), root, f.limits, f.blueprint.clone())?;
    let resumed = owner.resume_workspace(&f.session.principal_id, &f.session.session_id, third.result.digest(), TimestampNs(1_002))?;
    assert_eq!(resumed.result.revision, third.result);
    assert_eq!(resumed.workspace_checkpoint_digest, third.workspace_checkpoint_digest);
    assert!(resumed.result.revision.capsule().bookmarked_evidence.contains(&f.descriptor.subject_digest));
    assert!(resumed.result.revision.capsule().bookmarked_evidence.contains(&receipt));
    assert!(cursor_consumed(&f, &owner)?);
    assert_eq!(owner.remaining_token_budget(&f.session.principal_id, &f.session.session_id, TimestampNs(1_002))?, 3_976);
    let admissions = owner.admissions(&f.session.principal_id, &f.session.session_id, admitted_request, 1, TimestampNs(1_002))?;
    assert_eq!(admissions.len(), 1);
    assert_eq!(admissions[0].0, admission_root);
    assert_eq!(admissions[0].1.charged_tokens(), 512);
    assert!(owner.hydrate_context_slot_from_source(&f.session.principal_id, &f.publication,
        &f.read, &f.custody, TimestampNs(1_003)).is_err());
    assert_eq!(f.custody.reads.get(), 1);
    assert_eq!(owner.remaining_token_budget(&f.session.principal_id, &f.session.session_id, TimestampNs(1_003))?, 3_976);
    assert_eq!(owner.catalog().stored_payload_bytes(), f.blueprint.stored_payload_bytes());
    let journal = std::fs::read(f.path())?;
    assert!(!journal.windows(f.source.len()).any(|bytes| bytes == f.source));
    Ok(())
}

#[test]
fn rejected_workspace_rebase_keeps_the_prior_context_deliverable() -> TestResult {
    let (mut f, mut owner) = Fixture::new()?;
    owner.initialize_workspaces(WorkspaceLimits::default())?;
    let first = owner.publish_workspace(&f.session.principal_id, initial_workspace(&f)?, TimestampNs(1_000))?;
    f.advance(&mut owner)?;
    let (refresh, mut write) = rebase_request(&f.session, &first.result);
    write.capsule.open_obligations.clear();
    assert!(matches!(owner.rebase_workspace(&f.session.principal_id, refresh, write, TimestampNs(1_002)),
        Err(DurableWorkspaceError::Refused(WorkspaceError::PreservationRequired))));
    let root = owner.committed_root(); drop(owner);
    let mut owner = DurableDisclosureStore::open_existing(f.path(), root, f.limits, f.blueprint.clone())?;
    assert_eq!(owner.session(&f.session.principal_id, &f.session.session_id, TimestampNs(1_002))?, f.session);
    let resumed = owner.resume_workspace(&f.session.principal_id, &f.session.session_id, first.result.digest(), TimestampNs(1_002))?;
    assert!(!resumed.result.superseded);
    assert_eq!(resumed.workspace_checkpoint_digest, first.workspace_checkpoint_digest);
    assert!(!cursor_consumed(&f, &owner)?);
    assert_eq!(owner.remaining_token_budget(&f.session.principal_id, &f.session.session_id, TimestampNs(1_002))?, 4_488);
    let source = owner.hydrate_context_slot_from_source(&f.session.principal_id, &f.publication,
        &f.read, &f.custody, TimestampNs(1_002))?;
    assert_eq!(source.response.response.artifact.as_ref().ok_or("missing source")?.payload, f.source);
    assert_eq!(owner.remaining_token_budget(&f.session.principal_id, &f.session.session_id, TimestampNs(1_002))?, 3_976);
    assert_eq!(f.custody.reads.get(), 1);
    Ok(())
}

#[test]
fn committed_rebase_does_not_retarget_old_context_or_consume_its_cursor() -> TestResult {
    let (mut f, mut owner) = Fixture::new()?;
    owner.initialize_workspaces(WorkspaceLimits::default())?;
    let first = owner.publish_workspace(&f.session.principal_id, initial_workspace(&f)?, TimestampNs(1_000))?;
    f.advance(&mut owner)?;
    let (refresh, write) = rebase_request(&f.session, &first.result);
    let done = owner.rebase_workspace(&f.session.principal_id, refresh.clone(), write.clone(), TimestampNs(1_002))?;
    let root = owner.committed_root(); drop(owner);
    let mut owner = DurableDisclosureStore::open_existing(f.path(), root, f.limits, f.blueprint.clone())?;
    let session = owner.session(&f.session.principal_id, &f.session.session_id, TimestampNs(1_002))?;
    assert_eq!(session.current_anchor, refresh.current_anchor);
    assert_eq!(session.symbol_table_generation, f.session.symbol_table_generation + 1);
    let resumed = owner.resume_workspace(&f.session.principal_id, &f.session.session_id, done.result.digest(), TimestampNs(1_002))?;
    assert!(!resumed.result.rebase_required);
    let old = owner.resume_workspace(&f.session.principal_id, &f.session.session_id, first.result.digest(), TimestampNs(1_002))?;
    assert!(old.result.superseded && old.result.rebase_required);
    let retry = owner.rebase_workspace(&f.session.principal_id, refresh, write, TimestampNs(1_002))?;
    assert_eq!(retry.result, done.result);
    assert_eq!(retry.committed_root, root);
    // Remove the stale symbol-generation reason: the old context's anchor itself must refuse.
    f.read.generation = session.symbol_table_generation;
    assert!(owner.hydrate_context_slot_from_source(&f.session.principal_id, &f.publication,
        &f.read, &f.custody, TimestampNs(1_002)).is_err());
    assert_eq!(f.custody.reads.get(), 0);
    assert!(!cursor_consumed(&f, &owner)?);
    assert_eq!(owner.remaining_token_budget(&f.session.principal_id, &f.session.session_id, TimestampNs(1_002))?, 4_488);
    assert_eq!(owner.committed_root(), root);
    Ok(())
}

#[test]
fn workspace_persistence_failure_fences_source_disclosure_without_losing_recovery() -> TestResult {
    let (mut f, mut owner) = Fixture::new()?;
    owner.initialize_workspaces(WorkspaceLimits::default())?;
    let first = owner.publish_workspace(&f.session.principal_id, initial_workspace(&f)?, TimestampNs(1_000))?;
    f.advance(&mut owner)?;
    let root = owner.committed_root();
    // Inspection is read-only; no competing mutable session or journal owner is opened.
    let records = DurableSessionStore::inspect(f.path(), f.limits)?.records;
    drop(owner);
    let limited = DurableSessionLimits { max_records: records, ..f.limits };
    let mut owner = DurableDisclosureStore::open_existing(f.path(), root, limited, f.blueprint.clone())?;
    assert!(matches!(owner.publish_workspace(&f.session.principal_id, advance_workspace(&first.result), TimestampNs(1_001)),
        Err(DurableWorkspaceError::Durability(DurableSessionError::CapacityExceeded))));
    assert!(owner.needs_reconciliation());
    assert!(owner.hydrate_context_slot_from_source(&f.session.principal_id, &f.publication,
        &f.read, &f.custody, TimestampNs(1_002)).is_err());
    assert_eq!(f.custody.reads.get(), 0);
    assert_eq!(owner.committed_root(), root);
    drop(owner);
    let mut owner = DurableDisclosureStore::open_existing(f.path(), root, f.limits, f.blueprint.clone())?;
    let resumed = owner.resume_workspace(&f.session.principal_id, &f.session.session_id, first.result.digest(), TimestampNs(1_001))?;
    assert!(!resumed.result.superseded);
    assert!(!cursor_consumed(&f, &owner)?);
    assert_eq!(owner.remaining_token_budget(&f.session.principal_id, &f.session.session_id, TimestampNs(1_001))?, 4_488);
    let source = owner.hydrate_context_slot_from_source(&f.session.principal_id, &f.publication,
        &f.read, &f.custody, TimestampNs(1_002))?;
    assert_eq!(source.response.response.artifact.as_ref().ok_or("missing source")?.payload, f.source);
    assert_eq!(f.custody.reads.get(), 1);
    assert_eq!(owner.remaining_token_budget(&f.session.principal_id, &f.session.session_id, TimestampNs(1_002))?, 3_976);
    Ok(())
}
