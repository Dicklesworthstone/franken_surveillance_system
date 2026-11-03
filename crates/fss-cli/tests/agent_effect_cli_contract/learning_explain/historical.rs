#![forbid(unsafe_code)]
//! Explicit retained-learning recovery by a replacement session of the same owner and mission.
//! Current admission, immutable source provenance and session-scoped discovery remain separate.

use super::*;

use fss_core::{PrincipalId, SessionId, TimestampNs};
use fss_object::{HostSpoolIo, SpoolLock};
use fss_reference::agent_session::SessionRefresh;
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, DurableSessionStore, inspect_session_bytes,
};
use fss_reference::agent_session::work_claims::WorkClaimLimits;

fn open_selected_mission(
    directory: &OwnedDirectory,
    principal: &str,
    objective: &str,
) -> TestResult<Agent> {
    let root = directory.root();
    let (code, stdout) = run_fss(&[
        "session".into(),
        "open".into(),
        "--json".into(),
        "--root".into(),
        root.as_os_str().to_owned(),
        "--principal".into(),
        principal.into(),
        "--mission-text".into(),
        CAPTURE_MISSION.into(),
        "--objective".into(),
        objective.into(),
        "--view".into(),
        "epistemic_map".into(),
        "--budget-tokens".into(),
        "63000".into(),
    ])?;
    assert_eq!(code, Some(0), "{stdout}");
    let scratch = directory.0.join("historical-learning-scratch");
    fs::create_dir_all(&scratch)?;
    Ok(Agent {
        root,
        scratch,
        session: text(&parse(stdout.trim_end())?, &["sessionId"])?.to_owned(),
    })
}

fn cancel_original(captured: &Captured) -> TestResult {
    let (code, preview) = captured
        .agent
        .run("cancel", &["--session", &captured.agent.session])?;
    assert_eq!(code, Some(0), "{preview:?}");
    let approval = texts(&preview, &["proofPointers"])?
        .into_iter()
        .find_map(|pointer| {
            pointer
                .strip_prefix("session-cancellation-approval:")
                .map(str::to_owned)
        })
        .ok_or("session cancellation approval")?;
    let (code, closed) = captured.agent.run(
        "cancel",
        &["--session", &captured.agent.session, "--approve", &approval],
    )?;
    assert_eq!(code, Some(0), "{closed:?}");
    assert!(
        text(
            proposition(&closed, "session-cancellation:authority")?,
            &["statement"],
        )?
        .contains("authority cancelled;")
    );
    Ok(())
}

#[test]
fn selected_learning_replacement_recovers_cancelled_owners_exact_capture() -> TestResult {
    let (directory, event) = corroborated_event("historical-learning-cancelled")?;
    let captured = capture(&directory, &event)?;
    let (code, original_stdout) = run_fss(&args(
        &captured.agent,
        captured.root,
        &["--budget-tokens", "16000"],
    ))?;
    let (code, original) = captured.agent.answer(code, &original_stdout)?;
    assert_eq!(code, Some(0), "{original_stdout}");
    assert_selected(&original, &captured)?;
    cancel_original(&captured)?;

    // Replace the owner at a genuinely newer evidence anchor. The selected capture keeps its
    // old provenance even though current read admission and the response are anchored now.
    import(
        &directory,
        true,
        "sensor:historical-learning-replacement",
        now_ns()? - 10_000_000_000,
    )?;
    let current = open_selected_mission(&directory, &captured.principal, CAPTURE_OBJECTIVE)?;
    assert_ne!(current.session, captured.agent.session);
    let before = learning_tree(&current.root, &[""])?;
    let selected_args = args(&current, captured.root, &["--budget-tokens", "16000"]);
    let (code, stdout) = run_fss(&selected_args)?;
    let (code, selected) = current.answer(code, &stdout)?;
    assert_eq!(code, Some(0), "{stdout}");
    assert_selected_for(&selected, &captured, &current)?;
    assert_eq!(
        field(&selected, &["missionId"])?,
        field(&original, &["missionId"])?
    );
    assert_ne!(
        field(&selected, &["inputAnchor"])?,
        field(&original, &["inputAnchor"])?
    );
    assert_eq!(
        field(&selected, &["payload", "basisAnchor"])?,
        field(&original, &["payload", "basisAnchor"])?,
        "the historical learning basis is not rebased to the replacement session"
    );
    let remembered_basis = parse(text(
        proposition(&selected, "experience:basis")?,
        &["statement"],
    )?)?;
    assert_eq!(
        field(&selected, &["payload", "basisAnchor"])?,
        &remembered_basis,
        "the cognitive basis remains the authenticated historical experience basis"
    );
    assert_ne!(
        field(&selected, &["inputAnchor"])?,
        &remembered_basis,
        "current read authority must not be presented as the historical learning basis"
    );
    assert_eq!(
        proposition(&selected, "capture:custody")?,
        proposition(&original, "capture:custody")?,
        "all original custody identities, including source session and workspace, survive"
    );
    let current_authority = parse(text(
        proposition(&selected, "current:authority")?,
        &["statement"],
    )?)?;
    assert_eq!(text(&current_authority, &["sessionId"])?, current.session);
    assert_eq!(
        field(&current_authority, &["anchor"])?,
        field(&selected, &["inputAnchor"])?
    );
    let (code, retry) = run_fss(&selected_args)?;
    assert_eq!(code, Some(0), "{retry}");
    assert_eq!(retry, stdout, "cold historical reads are deterministic");
    assert_eq!(
        mcp_answer(
            &current,
            &captured.principal,
            captured.root,
            r#", "budget_tokens":16000"#,
            false,
        )?,
        stdout.trim_end(),
        "CLI and MCP use the same current admission and historical source closure"
    );

    let (code, orientation) = current.run(
        "orient",
        &["--session", &current.session, "--view", "epistemic_map"],
    )?;
    assert_eq!(code, Some(0), "{orientation:?}");
    let inventory = field(&orientation, &["payload", "contextPack", "items"])?
        .array()
        .ok_or("replacement protected context")?;
    for item in inventory {
        let content = text(item, &["content"])?;
        assert!(!content.contains(PRIVATE_STATEMENT));
        assert!(!content.contains(&captured.proposal.proposal_id));
    }
    let proofs = texts(&orientation, &["proofPointers"])?;
    for old in captured.proof_pointers.iter().take(3) {
        assert!(
            !proofs.contains(old),
            "explicit selection cannot broaden automatic discovery"
        );
    }
    assert_private_refusal(&captured.agent, captured.root, &[])?;
    assert_eq!(learning_tree(&current.root, &[""])?, before);
    assert_eq!(captured.relay.connections(), 0);
    Ok(())
}

#[test]
fn selected_learning_replacement_requires_current_owner_mission_grants_and_custody() -> TestResult {
    let (directory, event) = corroborated_event("historical-learning-scope")?;
    let captured = capture(&directory, &event)?;
    let current = open_selected_mission(&directory, &captured.principal, CAPTURE_OBJECTIVE)?;
    assert_ne!(current.session, captured.agent.session);

    // An independently admitted session can share the mission label without sharing the
    // objective, or share the exact stable mission while belonging to another principal.
    let other_objective = open_selected_mission(
        &directory,
        &captured.principal,
        "A different objective must not borrow the selected private learning.",
    )?;
    let refused = assert_private_refusal(&other_objective, captured.root, &[])?;
    assert_eq!(
        mcp_answer(
            &other_objective,
            &captured.principal,
            captured.root,
            "",
            true
        )?,
        refused.trim_end()
    );
    let other_principal = "principal:other-historical-learning-owner";
    let foreign = open_selected_mission(&directory, other_principal, CAPTURE_OBJECTIVE)?;
    let refused =
        assert_private_refusal(&foreign, captured.root, &["--principal", other_principal])?;
    assert_eq!(
        mcp_answer(&foreign, other_principal, captured.root, "", true)?,
        refused.trim_end()
    );

    let session_directory = current.root.join("agent/sessions");
    let journal_path = session_directory.join("journal.fssj");
    let pin_path = session_directory.join("ROOT");
    let journal_before = fs::read(&journal_path)?;
    let pin_before = fs::read(&pin_path)?;
    let pinned = ContentDigest::parse(std::str::from_utf8(&pin_before)?.trim())?;
    let limits = DurableSessionLimits::default();
    let inspected = inspect_session_bytes(&journal_before, limits, WorkClaimLimits::default())?;
    let current_id = SessionId::parse(&current.session)?;
    let principal = PrincipalId::parse(&captured.principal)?;
    let retained = inspected
        .sessions
        .iter()
        .find(|entry| entry.session.session_id == current_id)
        .ok_or("replacement session custody")?;
    let foreign_owner = inspected
        .sessions
        .iter()
        .find(|entry| entry.session.session_id.as_str() == foreign.session)
        .ok_or("foreign current session custody")?;
    assert_eq!(
        foreign_owner.session.mission_id,
        retained.session.mission_id
    );
    assert_ne!(
        foreign_owner.session.principal_id,
        retained.session.principal_id
    );
    for revoked in ["explain", "read", "privacy", "closed", "expired"] {
        {
            let _lock = SpoolLock::try_acquire(
                fs::File::open(session_directory.join("LOCK"))?,
                Arc::new(HostSpoolIo),
            )
            .map_err(|_| "replacement fixture session lock")?;
            let mut store = DurableSessionStore::open_existing_with_coordination(
                &journal_path,
                pinned,
                limits,
                WorkClaimLimits::default(),
            )?;
            match revoked {
                "closed" => store.close(&principal, &current_id, retained.last_observed_at)?,
                "expired" => {
                    assert!(
                        store
                            .session(
                                &principal,
                                &current_id,
                                TimestampNs(retained.session.expires_at_ns),
                            )
                            .is_err()
                    );
                }
                _ => {
                    let mut capabilities = retained.session.capabilities.clone();
                    let mut privacy_scope = retained.session.privacy_scope.clone();
                    match revoked {
                        "explain" => assert!(capabilities.remove("CAP-AGENT-EXPLAIN-001")),
                        "read" => assert!(capabilities.remove("CAP-AGENT-SESSION-READ-001")),
                        _ => assert!(privacy_scope.remove("private:property")),
                    }
                    store.refresh(
                        &principal,
                        &current_id,
                        SessionRefresh {
                            expected_session_digest: retained.session.session_digest(),
                            current_anchor: retained.session.current_anchor.clone(),
                            capabilities,
                            privacy_scope,
                        },
                        retained.last_observed_at,
                    )?;
                }
            }
            fs::write(&pin_path, format!("{}\n", store.committed_root()))?;
        }
        let revoked_tree = learning_tree(&current.root, &[""])?;
        let refused = assert_private_refusal(&current, captured.root, &[])?;
        assert_eq!(
            mcp_answer(&current, &captured.principal, captured.root, "", true)?,
            refused.trim_end(),
            "current {revoked} state must be enforced identically in both transports"
        );
        assert_eq!(learning_tree(&current.root, &[""])?, revoked_tree);
        // Restore only this test-owned baseline between independent native denial fixtures.
        fs::write(&journal_path, &journal_before)?;
        fs::write(&pin_path, &pin_before)?;
    }

    let digest = captured.episode_rendering.to_text();
    let source = current.root.join("agent/publications/spool/objects").join(
        digest
            .strip_prefix("sha256:")
            .ok_or("historical source digest")?,
    );
    let original = fs::read(&source)?;
    fs::remove_file(&source)?;
    let missing = learning_tree(&current.root, &[""])?;
    assert_private_refusal(&current, captured.root, &[])?;
    mcp_answer(&current, &captured.principal, captured.root, "", true)?;
    assert_eq!(learning_tree(&current.root, &[""])?, missing);
    assert!(
        !source.exists(),
        "historical reads never reconstruct lost custody"
    );
    fs::write(&source, original)?;

    // The old capture's valid mission cannot substitute for missing current mission custody.
    let workspace = inspected
        .workspace_revisions
        .iter()
        .filter(|revision| revision.capsule().session_id == current_id)
        .max_by_key(|revision| revision.capsule().revision)
        .ok_or("replacement workspace custody")?;
    let mission_digest = &workspace.capsule().objective_digest;
    let current_mission_slot = current
        .root
        .join("agent/publications")
        .join(fss_publication::LOCAL_ROOTS_DIR)
        .join(format!(
            "mission-{}{}",
            mission_digest
                .strip_prefix("sha256:")
                .ok_or("current mission digest")?,
            fss_publication::ROOT_RECORD_SUFFIX,
        ));
    let current_mission = fs::read(&current_mission_slot)?;
    fs::remove_file(&current_mission_slot)?;
    let missing_current_mission = learning_tree(&current.root, &[""])?;
    assert_private_refusal(&current, captured.root, &[])?;
    mcp_answer(&current, &captured.principal, captured.root, "", true)?;
    assert_eq!(
        learning_tree(&current.root, &[""])?,
        missing_current_mission
    );
    fs::write(&current_mission_slot, current_mission)?;

    let before = learning_tree(&current.root, &[""])?;
    let (code, stdout) = run_fss(&args(
        &current,
        captured.root,
        &["--budget-tokens", "16000"],
    ))?;
    let (code, restored) = current.answer(code, &stdout)?;
    assert_eq!(code, Some(0), "{stdout}");
    assert_selected_for(&restored, &captured, &current)?;
    assert_eq!(learning_tree(&current.root, &[""])?, before);
    assert_eq!(captured.relay.connections(), 0);
    Ok(())
}

#[test]
fn selected_learning_replacement_can_read_an_expired_original_without_reviving_it() -> TestResult {
    let (directory, event) = corroborated_event("historical-learning-expired")?;
    let captured = capture(&directory, &event)?;
    let current = open_selected_mission(&directory, &captured.principal, CAPTURE_OBJECTIVE)?;
    let session_directory = current.root.join("agent/sessions");
    let journal_path = session_directory.join("journal.fssj");
    let pin_path = session_directory.join("ROOT");
    let pin = ContentDigest::parse(fs::read_to_string(&pin_path)?.trim())?;
    let limits = DurableSessionLimits::default();
    let before = inspect_session_bytes(
        &fs::read(&journal_path)?,
        limits,
        WorkClaimLimits::default(),
    )?;
    let original = before
        .sessions
        .iter()
        .find(|entry| entry.session.session_id.as_str() == captured.agent.session)
        .ok_or("original learning session")?;
    {
        let _lock = SpoolLock::try_acquire(
            fs::File::open(session_directory.join("LOCK"))?,
            Arc::new(HostSpoolIo),
        )
        .map_err(|_| "historical expiry fixture lock")?;
        let mut store = DurableSessionStore::open_existing_with_coordination(
            &journal_path,
            pin,
            limits,
            WorkClaimLimits::default(),
        )?;
        assert!(
            store
                .session(
                    &original.session.principal_id,
                    &original.session.session_id,
                    TimestampNs(original.session.expires_at_ns),
                )
                .is_err()
        );
        fs::write(&pin_path, format!("{}\n", store.committed_root()))?;
    }
    let expired = learning_tree(&current.root, &[""])?;
    let (code, stdout) = run_fss(&args(
        &current,
        captured.root,
        &["--budget-tokens", "16000"],
    ))?;
    let (code, answer) = current.answer(code, &stdout)?;
    assert_eq!(code, Some(0), "{stdout}");
    assert_selected_for(&answer, &captured, &current)?;
    assert_eq!(
        mcp_answer(
            &current,
            &captured.principal,
            captured.root,
            r#", "budget_tokens":16000"#,
            false,
        )?,
        stdout.trim_end()
    );
    assert_private_refusal(&captured.agent, captured.root, &[])?;
    assert_eq!(learning_tree(&current.root, &[""])?, expired);
    let after =
        inspect_session_bytes(&fs::read(journal_path)?, limits, WorkClaimLimits::default())?;
    assert!(
        after
            .sessions
            .iter()
            .find(|entry| entry.session.session_id == original.session.session_id)
            .is_some_and(|entry| entry.closed)
    );
    assert_eq!(captured.relay.connections(), 0);
    Ok(())
}
