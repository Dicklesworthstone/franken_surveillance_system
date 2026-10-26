#![forbid(unsafe_code)]
//! Real CLI/MCP feedback-to-case lifecycle, immutable source custody and partial completion.

use super::*;
use fss_core::{InvestigationLifecycle, KnowledgeState};
use fss_reference::agent_session::checkpoint::journal::coordination::investigations::InvestigationRevision;
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, inspect_session_bytes,
};
use fss_reference::agent_session::work_claims::WorkClaimLimits;
use fss_reference::deployment_session::feedback::case::{CASE_REVIEW_LIFETIME_NS, identity};

/// These review cases retain three alternatives and explicit uncertainty. Select the registered
/// epistemic map view and a sufficient session grant instead of relying on the smaller brief.
fn open_case_agent(directory: &OwnedDirectory, mission: &str) -> TestResult<Agent> {
    let root = directory.root();
    let scratch = directory.0.join("scratch");
    fs::create_dir_all(&scratch)?;
    let (code, stdout) = run_fss(&[
        "session".into(),
        "open".into(),
        "--json".into(),
        "--root".into(),
        root.as_os_str().to_owned(),
        "--mission-text".into(),
        mission.into(),
        "--objective".into(),
        "Review retained feedback while preserving its alternatives and evidence custody.".into(),
        "--view".into(),
        "epistemic_map".into(),
        "--budget-tokens".into(),
        "100000".into(),
    ])?;
    assert_eq!(code, Some(0), "{stdout}");
    let agent = Agent {
        root,
        scratch,
        session: text(&parse(stdout.trim_end())?, &["sessionId"])?.to_owned(),
    };
    agent.answer(code, &stdout)?;
    Ok(agent)
}

fn feedback_args(
    agent: &Agent,
    target: &str,
    supporting: &str,
    contradicting: &str,
    statement: &str,
    disposition: &str,
) -> Vec<OsString> {
    agent.args(
        "feedback",
        &[
            "--session",
            &agent.session,
            "--target",
            target,
            "--kind",
            "adjudication",
            "--statement",
            statement,
            "--supporting",
            supporting,
            "--contradicting",
            contradicting,
            "--disposition",
            disposition,
        ],
    )
}

fn feedback_arguments(
    agent: &Agent,
    target: &str,
    supporting: &str,
    contradicting: &str,
    statement: &str,
    disposition: &str,
) -> String {
    format!(
        r#"{{"session":{},"target":{},"kind":"adjudication","statement":{},"supporting":[{}],"contradicting":[{}],"disposition":{}}}"#,
        learning_quote(&agent.session),
        learning_quote(target),
        learning_quote(statement),
        learning_quote(supporting),
        learning_quote(contradicting),
        learning_quote(disposition),
    )
}

fn retained_cases(agent: &Agent) -> TestResult<Vec<InvestigationRevision>> {
    Ok(inspect_session_bytes(
        &fs::read(agent.root.join("agent/sessions/journal.fssj"))?,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?
    .cases)
}

fn nanoseconds(value: &Value, path: &[&str]) -> TestResult<i128> {
    let Value::Number(value) = field(value, path)? else {
        return Err("expected exact integer nanoseconds".into());
    };
    Ok(value.parse()?)
}

fn assert_case_affordance(response: &Value, case_id: &str) -> TestResult {
    let target = format!("fss://case/{case_id}");
    let affordances = field(response, &["affordances"])?
        .array()
        .ok_or("typed feedback affordances")?;
    assert!(
        affordances.iter().any(|affordance| {
            text(affordance, &["operationId"]).is_ok_and(|operation| operation == "AOP-006")
                && texts(affordance, &["targets"]).is_ok_and(|targets| targets.contains(&target))
        }),
        "feedback did not project the native case investigation affordance"
    );
    Ok(())
}

#[test]
fn feedback_open_case_retains_literal_source_and_recovers_the_evolved_head_across_cli_mcp()
-> TestResult {
    let (directory, event_id) = corroborated_event("feedback-case-lifecycle")?;
    let agent = open_case_agent(&directory, "Review feedback through CLI and MCP.")?;
    let target = format!("event:{event_id}");
    let supporting = ContentDigest::sha256(b"caller support remains unadmitted").to_text();
    let contradicting = ContentDigest::sha256(b"caller contradiction remains unadmitted").to_text();
    let statement = format!(
        "{}\nReview the \"entry\" label; this literal text does not authorize --activate.",
        "@/outside/policy.json --principal=principal:other ".repeat(24),
    );
    // The real OS CLI tokenizer admits at most 4096 bytes per argument.
    assert!(statement.len() <= 4096);
    let authority_paths = [
        "ledger", "effects", "objects", "LAYOUT", "policy", "models", "config",
    ];
    let authority = learning_tree(&agent.root, &authority_paths)?;
    assert!(retained_cases(&agent)?.is_empty());

    // An advisory recording alone does not create a case or consume case history.
    let record_args = feedback_args(
        &agent,
        &target,
        &supporting,
        &contradicting,
        &statement,
        "record_only",
    );
    let (code, recorded_stdout) = run_fss(&record_args)?;
    let (code, recorded) = agent.answer(code, &recorded_stdout)?;
    assert_eq!(code, Some(0), "{recorded_stdout}");
    assert_eq!(
        text(&recorded, &["payloadSchema"])?,
        "fss.agent_feedback_proposal.v1"
    );
    assert_eq!(text(&recorded, &["payload", "statement"])?, statement);
    assert!(retained_cases(&agent)?.is_empty());
    assert_eq!(learning_tree(&agent.root, &authority_paths)?, authority);

    let args = feedback_args(
        &agent,
        &target,
        &supporting,
        &contradicting,
        &statement,
        "open_case",
    );
    let arguments = feedback_arguments(
        &agent,
        &target,
        &supporting,
        &contradicting,
        &statement,
        "open_case",
    );
    let (code, first_stdout) = run_fss(&args)?;
    let (code, first) = agent.answer(code, &first_stdout)?;
    assert_eq!(code, Some(0), "{first_stdout}");
    assert_eq!(text(&first, &["operationId"])?, "AOP-013");
    assert_eq!(text(&first, &["outcome"])?, "ok");
    assert_eq!(
        text(&first, &["payloadSchema"])?,
        "fss.agent_feedback_proposal.v1"
    );
    assert_eq!(text(&first, &["payload", "statement"])?, statement);
    assert_eq!(
        text(&first, &["payload", "requestedDisposition"])?,
        "open_case"
    );
    assert_eq!(
        field(&first, &["payload", "activePolicyMutation"])?,
        &Value::Bool(false)
    );
    assert_eq!(
        texts(&first, &["payload", "supportingEvidence"])?,
        vec![supporting.clone()]
    );
    assert_eq!(
        texts(&first, &["payload", "contradictingEvidence"])?,
        vec![contradicting.clone()]
    );
    assert_eq!(text(&first, &["epistemicState"])?, "unknown");
    assert_eq!(text(&first, &["completeness"])?, "partial");
    let pointers = texts(&first, &["proofPointers"])?;
    let feedback_root = ContentDigest::parse(&pointers[0])?;
    let case_id = identity(feedback_root);
    assert_eq!(pointers[2], case_id);
    let principal = text(&first, &["principalId"])?;
    let deadline = nanoseconds(&first, &["payload", "createdAtNs"])? + CASE_REVIEW_LIFETIME_NS;
    let cases = retained_cases(&agent)?;
    assert_eq!(cases.len(), 1);
    let original = &cases[0];
    assert_eq!(original.record().investigation_id, case_id);
    assert_eq!(original.record().revision, 1);
    assert_eq!(original.record().state, InvestigationLifecycle::Draft);
    assert_eq!(original.record().decision_deadline_ns, deadline);
    assert_eq!(
        original.record().investigation_digest().to_text(),
        pointers[3]
    );
    assert_eq!(original.digest().to_text(), pointers[4]);
    assert_eq!(original.record().knowns.len(), 1);
    assert_eq!(
        original.record().knowns[0].basis,
        vec![feedback_root.to_text()]
    );
    assert!(
        original.record().knowns[0]
            .text
            .contains("not the truth of its claim")
    );
    assert_eq!(original.record().hypotheses.len(), 3);
    assert!(original.record().hypotheses.iter().all(|hypothesis| {
        hypothesis.epistemic_state == KnowledgeState::Unknown
            && hypothesis.evidence.is_empty()
            && hypothesis.contradictions.is_empty()
    }));
    assert!(
        original
            .record()
            .unknowns
            .iter()
            .all(|statement| statement.epistemic_state == KnowledgeState::Unknown)
    );
    assert!(original.record().probes.is_empty());
    assert_case_affordance(&first, &case_id)?;
    assert!(
        texts(&first, &["executionBoundary", "completed"])?
            .iter()
            .any(|line| line.contains(&case_id) && line.contains(&pointers[4]))
    );

    let retained_feedback = learning_tree(&agent.root, &["agent/publications"])?;
    let (code, retry_stdout) = run_fss(&args)?;
    let (code, retry) = agent.answer(code, &retry_stdout)?;
    assert_eq!(code, Some(0), "{retry_stdout}");
    assert_eq!(field(&retry, &["payload"])?, field(&first, &["payload"])?);
    assert_eq!(
        text(&retry, &["decisionFingerprint"])?,
        text(&first, &["decisionFingerprint"])?
    );
    let retry_pointers = texts(&retry, &["proofPointers"])?;
    assert_eq!(&retry_pointers[..5], &pointers[..5]);
    assert_eq!(retained_cases(&agent)?, cases);
    assert_eq!(
        learning_tree(&agent.root, &["agent/publications"])?,
        retained_feedback
    );
    // Open retries are journaled native commands, so receipt roots can legitimately differ.
    assert_ne!(retry_pointers[5], pointers[5]);

    let (code, inspected) = agent.run(
        "investigate",
        &[
            "--session",
            &agent.session,
            "--transition",
            "inspect",
            "--case",
            &case_id,
        ],
    )?;
    assert_eq!(code, Some(0), "{inspected:?}");
    assert_eq!(text(&inspected, &["payload", "investigationId"])?, case_id);
    assert_eq!(
        text(&inspected, &["payload", "revisionDigest"])?,
        pointers[4]
    );
    let (code, active) = agent.run(
        "investigate",
        &[
            "--session",
            &agent.session,
            "--transition",
            "activate",
            "--case",
            &case_id,
            "--expected",
            &pointers[4],
        ],
    )?;
    assert_eq!(code, Some(0), "{active:?}");
    assert_eq!(text(&active, &["payload", "state"])?, "active");
    assert_eq!(field(&active, &["payload", "revision"])?.integer(), Some(2));
    let active_revision = text(&active, &["payload", "revisionDigest"])?;

    let (code, evolved_stdout) = run_fss(&args)?;
    let (code, evolved) = agent.answer(code, &evolved_stdout)?;
    assert_eq!(code, Some(0), "{evolved_stdout}");
    assert_eq!(field(&evolved, &["payload"])?, field(&first, &["payload"])?);
    let evolved_pointers = texts(&evolved, &["proofPointers"])?;
    assert_eq!(&evolved_pointers[..4], &pointers[..4]);
    assert_eq!(evolved_pointers[4], active_revision);
    assert_ne!(
        text(&evolved, &["decisionFingerprint"])?,
        text(&first, &["decisionFingerprint"])?
    );
    assert_case_affordance(&evolved, &case_id)?;
    let evolved_cases = retained_cases(&agent)?;
    assert_eq!(evolved_cases.len(), 1);
    assert_eq!(evolved_cases[0].record().revision, 2);
    assert_eq!(
        evolved_cases[0].record().state,
        InvestigationLifecycle::Active
    );
    assert_eq!(evolved_cases[0].record().decision_deadline_ns, deadline);

    // Cold MCP uses the exact same native result and response projection. Only its command
    // journal receipt changes; it does not reset the draft, add a case or renew its deadline.
    let mcp_stdout = learning_mcp(&agent, principal, &arguments, false)?;
    let mcp = parse(&mcp_stdout)?;
    assert_eq!(field(&mcp, &["payload"])?, field(&evolved, &["payload"])?);
    assert_eq!(
        text(&mcp, &["decisionFingerprint"])?,
        text(&evolved, &["decisionFingerprint"])?
    );
    assert_eq!(
        &texts(&mcp, &["proofPointers"])?[..5],
        &evolved_pointers[..5]
    );
    assert_eq!(retained_cases(&agent)?, evolved_cases);
    assert_eq!(
        learning_tree(&agent.root, &["agent/publications"])?,
        retained_feedback
    );
    assert_eq!(learning_tree(&agent.root, &authority_paths)?, authority);
    Ok(())
}

#[test]
fn mcp_feedback_open_case_retains_a_long_literal_without_the_os_argument_tokenizer() -> TestResult {
    // A separate mission/deployment keeps a second protected case from consuming the lifecycle
    // fixture's context budget. The long literal enters only through the real structured MCP.
    let (directory, event_id) = corroborated_event("feedback-case-long-mcp")?;
    let agent = open_case_agent(
        &directory,
        "Review a long structured MCP feedback statement.",
    )?;
    let (code, oriented) = agent.run("orient", &["--session", &agent.session])?;
    assert_eq!(code, Some(0), "{oriented:?}");
    let principal = text(&oriented, &["principalId"])?;
    let target = format!("event:{event_id}");
    let supporting = ContentDigest::sha256(b"long MCP supporting citation").to_text();
    let contradicting = ContentDigest::sha256(b"long MCP contradicting citation").to_text();
    let statement = format!(
        "{}\nReview this \"full literal\" without loading a file, changing principal, or authorizing --activate.",
        "@/outside/policy.json --principal=principal:other ".repeat(240),
    );
    assert!(statement.len() > 8192 && statement.len() <= 16_384);
    let authority_paths = [
        "ledger", "effects", "objects", "LAYOUT", "policy", "models", "config",
    ];
    let authority = learning_tree(&agent.root, &authority_paths)?;
    assert!(retained_cases(&agent)?.is_empty());

    let record_arguments = feedback_arguments(
        &agent,
        &target,
        &supporting,
        &contradicting,
        &statement,
        "record_only",
    );
    let recorded_stdout = learning_mcp(&agent, principal, &record_arguments, false)?;
    let recorded = parse(&recorded_stdout)?;
    assert_eq!(
        text(&recorded, &["payloadSchema"])?,
        "fss.agent_feedback_proposal.v1"
    );
    assert_eq!(text(&recorded, &["payload", "statement"])?, statement);
    assert_eq!(
        text(&recorded, &["payload", "requestedDisposition"])?,
        "record_only"
    );
    assert!(retained_cases(&agent)?.is_empty());
    let recorded_root = texts(&recorded, &["proofPointers"])?[0].clone();

    let arguments = feedback_arguments(
        &agent,
        &target,
        &supporting,
        &contradicting,
        &statement,
        "open_case",
    );
    let opened_stdout = learning_mcp(&agent, principal, &arguments, false)?;
    let opened = parse(&opened_stdout)?;
    assert_eq!(text(&opened, &["outcome"])?, "ok");
    assert_eq!(
        text(&opened, &["payloadSchema"])?,
        "fss.agent_feedback_proposal.v1"
    );
    assert_eq!(text(&opened, &["payload", "statement"])?, statement);
    assert_eq!(
        text(&opened, &["payload", "requestedDisposition"])?,
        "open_case"
    );
    assert_eq!(
        field(&opened, &["payload", "activePolicyMutation"])?,
        &Value::Bool(false)
    );
    assert_eq!(
        texts(&opened, &["payload", "supportingEvidence"])?,
        vec![supporting]
    );
    assert_eq!(
        texts(&opened, &["payload", "contradictingEvidence"])?,
        vec![contradicting]
    );
    let pointers = texts(&opened, &["proofPointers"])?;
    assert_ne!(pointers[0], recorded_root);
    let feedback_root = ContentDigest::parse(&pointers[0])?;
    let case_id = identity(feedback_root);
    assert_eq!(pointers[2], case_id);
    let cases = retained_cases(&agent)?;
    assert_eq!(cases.len(), 1);
    let case = &cases[0];
    assert_eq!(case.record().investigation_id, case_id);
    assert_eq!(case.record().revision, 1);
    assert_eq!(case.record().state, InvestigationLifecycle::Draft);
    assert_eq!(case.record().knowns[0].basis, vec![feedback_root.to_text()]);
    assert_eq!(case.record().hypotheses.len(), 3);
    assert!(case.record().hypotheses.iter().all(|hypothesis| {
        hypothesis.epistemic_state == KnowledgeState::Unknown
            && hypothesis.evidence.is_empty()
            && hypothesis.contradictions.is_empty()
    }));
    assert!(
        case.record()
            .unknowns
            .iter()
            .all(|statement| statement.epistemic_state == KnowledgeState::Unknown)
    );
    assert!(case.record().probes.is_empty());
    assert!(!case.record().question.contains("@/outside"));
    assert_eq!(
        case.record().decision_deadline_ns,
        nanoseconds(&opened, &["payload", "createdAtNs"])? + CASE_REVIEW_LIFETIME_NS,
    );
    assert_case_affordance(&opened, &case_id)?;

    // The corresponding source stays complete, while case hydration uses bounded references.
    let (code, inspected) = agent.run(
        "investigate",
        &[
            "--session",
            &agent.session,
            "--transition",
            "inspect",
            "--case",
            &case_id,
        ],
    )?;
    assert_eq!(code, Some(0), "{inspected:?}");
    assert_eq!(text(&inspected, &["payload", "investigationId"])?, case_id);
    assert_eq!(
        text(&inspected, &["payload", "revisionDigest"])?,
        pointers[4]
    );
    let publications = learning_tree(&agent.root, &["agent/publications"])?;
    let retried_stdout = learning_mcp(&agent, principal, &arguments, false)?;
    let retried = parse(&retried_stdout)?;
    assert_eq!(
        field(&retried, &["payload"])?,
        field(&opened, &["payload"])?
    );
    assert_eq!(
        text(&retried, &["decisionFingerprint"])?,
        text(&opened, &["decisionFingerprint"])?
    );
    assert_eq!(&texts(&retried, &["proofPointers"])?[..5], &pointers[..5]);
    assert_eq!(retained_cases(&agent)?, cases);
    assert_eq!(
        learning_tree(&agent.root, &["agent/publications"])?,
        publications
    );
    assert_eq!(learning_tree(&agent.root, &authority_paths)?, authority);
    Ok(())
}

#[test]
fn feedback_case_scope_refusal_preserves_the_original_proposal_in_cli_and_mcp() -> TestResult {
    let (directory, event_id) = corroborated_event("feedback-case-scope")?;
    let owner = Agent::open(&directory)?;
    let relay: SocketAddr = "127.0.0.1:9".parse()?;
    let (code, planned) = owner.plan(&event_id, relay, &[])?;
    assert_eq!(code, Some(0), "{planned:?}");
    let plan_id = text(&planned, &["payload", "planId"])?;
    let principal = text(&planned, &["principalId"])?;
    let supporting = texts(&planned, &["proofPointers"])?[0].clone();
    let contradicting = ContentDigest::sha256(b"unverified contrary explanation").to_text();
    let (code, opened_stdout) = run_fss(&[
        "session".into(),
        "open".into(),
        "--json".into(),
        "--root".into(),
        owner.root.as_os_str().to_owned(),
        "--mission".into(),
        "Review a separate mission.".into(),
        "--objective".into(),
        "Keep other sessions' plans outside this private review.".into(),
    ])?;
    let (code, opened) = owner.answer(code, &opened_stdout)?;
    assert_eq!(code, Some(0), "{opened_stdout}");
    let other = Agent {
        root: owner.root.clone(),
        scratch: owner.scratch.clone(),
        session: text(&opened, &["sessionId"])?.to_owned(),
    };
    assert_ne!(owner.session, other.session);
    let target = format!("plan:{plan_id}");
    let statement = "Request review of this named plan while preserving its original ownership.";
    let args = feedback_args(
        &other,
        &target,
        &supporting,
        &contradicting,
        statement,
        "open_case",
    );
    let arguments = feedback_arguments(
        &other,
        &target,
        &supporting,
        &contradicting,
        statement,
        "open_case",
    );
    let authority_paths = [
        "ledger", "effects", "objects", "LAYOUT", "policy", "models", "config",
    ];
    let authority = learning_tree(&owner.root, &authority_paths)?;
    let before_cases = retained_cases(&owner)?;
    let (code, refused_stdout) = run_fss(&args)?;
    let (code, refused) = other.answer(code, &refused_stdout)?;
    assert_eq!(code, Some(5), "{refused_stdout}");
    assert_eq!(text(&refused, &["outcome"])?, "partial");
    assert_eq!(text(&refused, &["errorId"])?, "ERR-PRECONDITION-STALE-001");
    assert_eq!(
        text(&refused, &["payloadSchema"])?,
        "fss.agent_feedback_proposal.v1"
    );
    assert_eq!(text(&refused, &["payload", "statement"])?, statement);
    assert_eq!(
        field(&refused, &["payload", "activePolicyMutation"])?,
        &Value::Bool(false)
    );
    let feedback_id = text(&refused, &["payload", "feedbackId"])?;
    let pointers = texts(&refused, &["proofPointers"])?;
    assert!(
        texts(&refused, &["executionBoundary", "completed"])?
            .iter()
            .any(|line| line.contains(feedback_id) && line.contains(&pointers[0]))
    );
    assert!(
        texts(&refused, &["executionBoundary", "notStarted"])?
            .iter()
            .any(|line| line.contains("No new investigation case revision"))
    );
    assert!(texts(&refused, &["executionBoundary", "possiblyOccurred"])?.is_empty());
    assert!(
        field(&refused, &["affordances"])?
            .array()
            .ok_or("refusal affordances")?
            .is_empty()
    );
    assert_eq!(retained_cases(&owner)?, before_cases);
    let publications = learning_tree(&owner.root, &["agent/publications"])?;
    let mcp_stdout = learning_mcp(&other, principal, &arguments, true)?;
    let mcp = parse(&mcp_stdout)?;
    assert_eq!(field(&mcp, &["payload"])?, field(&refused, &["payload"])?);
    assert_eq!(texts(&mcp, &["proofPointers"])?, pointers);
    assert_eq!(
        text(&mcp, &["decisionFingerprint"])?,
        text(&refused, &["decisionFingerprint"])?
    );
    assert_eq!(
        learning_tree(&owner.root, &["agent/publications"])?,
        publications
    );
    assert_eq!(retained_cases(&owner)?, before_cases);
    assert_eq!(learning_tree(&owner.root, &authority_paths)?, authority);
    Ok(())
}
