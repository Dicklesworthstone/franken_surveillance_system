#![forbid(unsafe_code)]
//! Real native open retries at the committed-session / missing-workspace crash boundary.

use std::collections::BTreeSet;

use super::*;
use crate::agent_session::SessionRefresh;
use crate::agent_session::checkpoint::journal::workspace::{
    WORKSPACE_INIT_RECORD_KIND, WORKSPACE_WRITE_RECORD_KIND,
};
use crate::deployment_session::{
    OpenedSession, SESSION_ROOT_PIN_FILE, SessionJournal, hex, publish_record,
};
use fss_core::{
    AgentFeedbackProposal, CanonicalEncode, FeedbackPrivacyClass, FeedbackProposalKind,
    RequestedDisposition,
};
use fss_publication::SlotName;

/// Recreate an actual opening crash prefix without duplicating production initialization.
/// Mission publication precedes session open. The original pin still names workspace-store
/// initialization when the session append commits and the first workspace append has not begun.
fn interrupt_before_first_workspace(root: &Path) -> TestResult<Vec<u8>> {
    let full = journal_bytes(root)?;
    let report = fss_ledger::recover_bytes(&full)?;
    assert!(report.incomplete_tail().is_none());
    let first_workspace = report
        .records()
        .iter()
        .position(|record| record.kind() == WORKSPACE_WRITE_RECORD_KIND)
        .ok_or("initial workspace append")?;
    let prefix_records = &report.records()[..first_workspace];
    let prior_pin = prefix_records
        .iter()
        .rev()
        .find(|record| record.kind() == WORKSPACE_INIT_RECORD_KIND)
        .ok_or("original workspace-store initialization pin")?
        .root();
    let prefix_len = usize::try_from(
        prefix_records
            .iter()
            .map(|record| record.framed_len())
            .sum::<u64>(),
    )?;
    let prefix = full[..prefix_len].to_vec();
    let recovered = fss_ledger::recover_bytes(&prefix)?;
    assert_eq!(recovered.records().len(), prefix_records.len());
    assert_ne!(
        recovered.last_root(),
        prior_pin,
        "session open committed after the original pin"
    );
    assert!(recovered.incomplete_tail().is_none());
    fs::write(
        root.join(SESSIONS_RELPATH).join(SESSION_JOURNAL_FILE),
        &prefix,
    )?;
    fs::write(
        root.join(SESSIONS_RELPATH).join(SESSION_ROOT_PIN_FILE),
        format!("{prior_pin}\n"),
    )?;
    Ok(prefix)
}

fn publish_changed_history(root: &Path, opened: &OpenedSession) -> TestResult {
    // These are canonical retained-report fixtures. They establish advisory history only;
    // they do not create a physical event, policy activation or effect.
    for identity in ["opening-change-a", "opening-change-b"] {
        let feedback_id = format!("feedback:{identity}");
        let proposal = AgentFeedbackProposal::new(
            feedback_id.clone(),
            opened.session.principal_id.clone(),
            opened.session.session_id.clone(),
            opened.session.current_anchor.clone(),
            "{\"id\":\"event:historical-fixture\",\"kind\":\"event\"}",
            FeedbackProposalKind::HardNegativeCandidate,
            "A retained negative report changes the proposed opening context.",
            Vec::new(),
            Vec::new(),
            RequestedDisposition::RecordOnly,
            FeedbackPrivacyClass::Private,
            opened.session.created_at_ns,
        )?;
        let slot = SlotName::parse(&format!(
            "feedback-{}",
            hex(ContentDigest::sha256(feedback_id.as_bytes())),
        ))?;
        publish_record(
            root,
            &slot,
            "agent-feedback",
            &proposal.try_canonical_bytes()?,
            &[b"{}".to_vec()],
            None,
        )?;
    }
    Ok(())
}

#[test]
fn unchanged_context_completes_interrupted_open_and_exact_retries_do_not_append() -> TestResult {
    let fixture = Fixture::new("native-opening-interruption", SITE)?;
    let request = open_request()?;
    let authority = fixture.authority_digests()?;
    let original = open_session(&fixture.root, &request)?;
    let completed_bytes = journal_bytes(&fixture.root)?;
    interrupt_before_first_workspace(&fixture.root)?;

    let recovered = open_session(&fixture.root, &request)?;
    assert_eq!(recovered.session, original.session);
    assert_eq!(recovered.mission, original.mission);
    assert_eq!(recovered.mission_root, original.mission_root);
    assert_eq!(recovered.request_digest, original.request_digest);
    assert_eq!(recovered.revision, original.revision);
    assert_eq!(journal_bytes(&fixture.root)?, completed_bytes);
    let retry = open_session(&fixture.root, &request)?;
    assert_eq!(retry.revision, recovered.revision);
    assert_eq!(retry.journal_root, recovered.journal_root);
    assert_eq!(journal_bytes(&fixture.root)?, completed_bytes);
    assert_eq!(fixture.authority_digests()?, authority);
    Ok(())
}

#[test]
fn changed_context_cannot_replace_the_lost_opening_frame() -> TestResult {
    let fixture = Fixture::new("native-opening-changed-context", SITE)?;
    let request = open_request()?;
    let original = open_session(&fixture.root, &request)?;
    let prefix = interrupt_before_first_workspace(&fixture.root)?;
    publish_changed_history(&fixture.root, &original)?;
    assert_eq!(
        crate::deployment_session::trauma_guard::derive_trauma_guard_warnings(
            &fixture.root,
            &request.principal,
            original.session.created_at_ns,
        )?
        .len(),
        1
    );
    let authority = fixture.authority_digests()?;

    // The original owner checks opening_digest before any new workspace can be appended.
    assert!(matches!(
        open_session(&fixture.root, &request),
        Err(DeploymentSessionError::SessionUnknown)
    ));
    assert_eq!(journal_bytes(&fixture.root)?, prefix);
    let mut journal = SessionJournal::open(&fixture.root)?;
    let live = journal.store.session(
        &request.principal,
        &original.session.session_id,
        TimestampNs(original.session.created_at_ns),
    )?;
    assert_eq!(live, original.session);
    assert!(
        journal
            .store
            .workspace_head(
                &request.principal,
                &live.session_id,
                TimestampNs(live.created_at_ns)
            )
            .is_err()
    );
    journal.commit_pin()?;
    assert_eq!(fixture.authority_digests()?, authority);
    Ok(())
}

#[test]
fn narrowed_incomplete_open_is_refused_before_private_mission_custody_is_read() -> TestResult {
    for (tag, remove_privacy) in [
        ("native-opening-private-denied", true),
        ("native-opening-capability-denied", false),
    ] {
        let fixture = Fixture::new(tag, SITE)?;
        let request = open_request()?;
        let original = open_session(&fixture.root, &request)?;
        interrupt_before_first_workspace(&fixture.root)?;
        let now = TimestampNs(original.session.created_at_ns);
        let mut journal = SessionJournal::open(&fixture.root)?;
        let mut capabilities = original.session.capabilities.clone();
        let privacy_scope = if remove_privacy {
            BTreeSet::new()
        } else {
            assert!(capabilities.remove("CAP-AGENT-SITUATION-READ-001"));
            original.session.privacy_scope.clone()
        };
        let narrowed = journal.store.refresh(
            &request.principal,
            &original.session.session_id,
            SessionRefresh {
                expected_session_digest: original.session.session_digest(),
                current_anchor: original.session.current_anchor.clone(),
                capabilities,
                privacy_scope,
            },
            now,
        )?;
        journal.commit_pin()?;
        drop(journal);
        let before = journal_bytes(&fixture.root)?;

        // A mission read would produce StoreInvalid. Authority must refuse first, including
        // when the original private record's object has become unreadable by verification.
        let metadata = fixture
            .root
            .join(PUBLICATIONS_RELPATH)
            .join("spool")
            .join("objects")
            .join(hex(original.mission.digest()));
        assert!(metadata.is_file());
        fs::write(&metadata, b"corrupted private retained mission")?;
        let error = open_session(&fixture.root, &request)
            .err()
            .ok_or("narrowed retry refused")?;
        assert!(matches!(error, DeploymentSessionError::SessionStale(reason)
            if reason.contains("original authority projection")));
        assert_eq!(journal_bytes(&fixture.root)?, before);
        let mut journal = SessionJournal::open(&fixture.root)?;
        assert_eq!(
            journal
                .store
                .session(&request.principal, &narrowed.session_id, now)?,
            narrowed
        );
        journal.commit_pin()?;
    }
    Ok(())
}

#[test]
fn incomplete_open_never_recreates_missing_retained_mission_publication() -> TestResult {
    let fixture = Fixture::new("native-opening-missing-mission", SITE)?;
    let request = open_request()?;
    open_session(&fixture.root, &request)?;
    let prefix = interrupt_before_first_workspace(&fixture.root)?;
    let publications = fixture.root.join(PUBLICATIONS_RELPATH);
    fs::remove_dir_all(&publications)?;
    assert!(matches!(open_session(&fixture.root, &request),
        Err(DeploymentSessionError::StoreInvalid(reason))
            if reason.contains("retained opening mission is missing")));
    assert!(!publications.exists());
    assert_eq!(journal_bytes(&fixture.root)?, prefix);
    Ok(())
}
