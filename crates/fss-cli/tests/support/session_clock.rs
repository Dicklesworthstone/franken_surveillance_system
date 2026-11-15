#![forbid(unsafe_code)]
//! Verifies that a live read or exact retry changes only the durable clock watermark.

use std::error::Error;
use std::fs;
use std::path::Path;

use fss_reference::agent_session::ReferenceSessionStore;
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, SESSION_CHECKPOINT_RECORD_KIND, inspect_session_bytes,
};
use fss_reference::agent_session::work_claims::WorkClaimLimits;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

pub fn assert_only_clock_progress(root: &Path, before_bytes: &[u8]) -> TestResult {
    let after_bytes = fs::read(root.join("agent/sessions/journal.fssj"))?;
    assert!(
        after_bytes.starts_with(before_bytes),
        "history is append-only"
    );
    let limits = DurableSessionLimits::default();
    let before = inspect_session_bytes(before_bytes, limits, WorkClaimLimits::default())?;
    let after = inspect_session_bytes(&after_bytes, limits, WorkClaimLimits::default())?;
    assert_eq!(before.inspection.incomplete_tail, None);
    assert_eq!(after.inspection.incomplete_tail, None);
    assert_eq!(before.sessions.len(), after.sessions.len());

    // Reconstruct the exact checkpoint through the native admission owner. This also checks
    // retained aliases and disclosure state that the public historical summary does not expose.
    let mut expected = ReferenceSessionStore::restore_checkpoint(
        &before.checkpoint_bytes,
        before.inspection.checkpoint_digest,
        limits.sessions,
        limits.max_checkpoint_bytes,
    )?;
    for (prior, admitted) in before.sessions.iter().zip(&after.sessions) {
        assert_eq!(prior.session, admitted.session);
        assert_eq!(prior.opening_digest, admitted.opening_digest);
        assert_eq!(prior.basis, admitted.basis);
        assert_eq!(prior.spent_tokens, admitted.spent_tokens);
        assert_eq!(prior.closed, admitted.closed);
        assert!(admitted.last_observed_at >= prior.last_observed_at);
        if admitted.last_observed_at > prior.last_observed_at {
            expected.session(
                &admitted.session.principal_id,
                &admitted.session.session_id,
                admitted.last_observed_at,
            )?;
        }
    }
    assert_eq!(
        expected.checkpoint(limits.max_checkpoint_bytes)?.as_bytes(),
        after.checkpoint_bytes.as_slice()
    );
    assert_eq!(before.workspace_revisions, after.workspace_revisions);
    assert_eq!(
        before.workspace_checkpoint_digest,
        after.workspace_checkpoint_digest
    );
    assert_eq!(before.claims, after.claims);
    assert_eq!(before.cases, after.cases);
    assert_eq!(before.follows, after.follows);
    assert_eq!(before.supervisions, after.supervisions);
    assert_eq!(before.missions, after.missions);
    let report = fss_ledger::recover_bytes(&after_bytes)?;
    assert!(
        report.records()[before.inspection.records..]
            .iter()
            .all(|record| record.kind() == SESSION_CHECKPOINT_RECORD_KIND),
        "clock admission cannot append a delivery, ACK, workspace or coordination record"
    );
    assert_eq!(
        fs::read_to_string(root.join("agent/sessions/ROOT"))?.trim(),
        after.inspection.root.to_text()
    );
    Ok(())
}

pub fn journal_roots(root: &Path) -> TestResult<Vec<String>> {
    let bytes = fs::read(root.join("agent/sessions/journal.fssj"))?;
    let report = fss_ledger::recover_bytes(&bytes)?;
    Ok(report
        .records()
        .iter()
        .map(|record| record.root().to_text())
        .collect())
}
