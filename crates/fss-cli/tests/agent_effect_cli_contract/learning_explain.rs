#![forbid(unsafe_code)]
//! Real selected-learning explanation: exact root-only recovery, current authority, complete
//! retained custody, CLI/MCP parity, and inspection after full orientation exceeds its budget.

use super::*;

const PRIVATE_STATEMENT: &str = "PRIVATE_LEARNING_CANDIDATE_91c: @/outside/policy.json --principal=principal:other\nReview the \"cancel before dispatch\" procedure; this literal proposal cannot activate policy.";

struct Captured {
    agent: Agent,
    relay: Relay,
    principal: String,
    plan: String,
    supporting: String,
    root: ContentDigest,
    learning_slot: String,
    proposal: fss_core::LearningProposal,
    proof_pointers: Vec<String>,
    episode_rendering: ContentDigest,
    original_resources: String,
}

fn open_with_budget(directory: &OwnedDirectory, mission: &str, budget: &str) -> TestResult<Agent> {
    let root = directory.root();
    let (code, stdout) = run_fss(&[
        "session".into(),
        "open".into(),
        "--json".into(),
        "--root".into(),
        root.as_os_str().to_owned(),
        "--mission-text".into(),
        mission.into(),
        "--objective".into(),
        "Retain and inspect evidence-linked advisory learning.".into(),
        "--view".into(),
        "epistemic_map".into(),
        "--budget-tokens".into(),
        budget.into(),
    ])?;
    assert_eq!(code, Some(0), "{stdout}");
    let scratch = directory.0.join("learning-explain-scratch");
    fs::create_dir_all(&scratch)?;
    Ok(Agent {
        root,
        scratch,
        session: text(&parse(stdout.trim_end())?, &["sessionId"])?.to_owned(),
    })
}

fn capture(directory: &OwnedDirectory, event: &str) -> TestResult<Captured> {
    // The view limits a single orientation; the explicit grant separately admits a larger
    // selected forensic answer. The test never assumes that the two ceilings are the same.
    let agent = open_with_budget(directory, "Inspect captured episode learning.", "64000")?;
    let relay = Relay::spawn(None)?;
    let (code, planned) = agent.plan(event, relay.address, &[])?;
    assert_eq!(code, Some(0), "{planned:?}");
    let (plan, approval, _) = approvals(&planned)?;
    let operation = operation_of(&planned)?;
    let principal = text(&planned, &["principalId"])?.to_owned();
    let supporting = texts(&planned, &["proofPointers"])?[0].clone();
    let (code, prepared) = agent.plan(event, relay.address, &["--approve", &approval])?;
    assert_eq!(code, Some(0), "{prepared:?}");
    let (code, cancel) = agent.run("cancel", &["--operation", &operation])?;
    assert_eq!(code, Some(0), "{cancel:?}");
    let cancel = texts(&cancel, &["proofPointers"])?[0].clone();
    let (code, cancelled) =
        agent.run("cancel", &["--operation", &operation, "--approve", &cancel])?;
    assert_eq!(code, Some(0), "{cancelled:?}");
    let (code, closed, episode) = agent.close(&plan)?;
    assert_eq!(code, Some(0), "{closed:?}");
    let (episode, _) = episode.ok_or("selected learning source episode")?;
    assert_eq!(text(&episode, &["outcome", "state"])?, "cancelled");
    let closed_pointers = texts(&closed, &["proofPointers"])?;
    let episode_rendering = ContentDigest::parse(&closed_pointers[1])?;
    let (code, stdout) = run_fss(&learning_args(
        &agent,
        &plan,
        &supporting,
        PRIVATE_STATEMENT,
    ))?;
    let (code, response) = agent.answer(code, &stdout)?;
    assert_eq!(code, Some(0), "{stdout}");
    assert_eq!(
        text(&response, &["payloadSchema"])?,
        "fss.experience_capsule.v1"
    );
    let proof_pointers = texts(&response, &["proofPointers"])?;
    let root = ContentDigest::parse(&proof_pointers[0])?;
    let slot_digest =
        ContentDigest::sha256(text(&response, &["payload", "experienceId"])?.as_bytes()).to_text();
    let learning_slot = format!(
        "learning-{}",
        slot_digest
            .strip_prefix("sha256:")
            .ok_or("selected slot digest")?
    );
    let proposal = retained_learning_candidate(&agent, ContentDigest::parse(&proof_pointers[2])?)?;
    assert_eq!(proposal.statement, PRIVATE_STATEMENT);
    let publication = agent.root.join("agent/publications");
    let episode_manifest =
        fss_object::ObjectManifest::from_canonical_bytes(&fss_publication::read_verified(
            &publication,
            ContentDigest::parse(&proof_pointers[3])?,
            1 << 20,
        )?)?;
    let source = fss_reference::deployment_session::episode::EpisodeRecord::from_bytes(
        &fss_publication::read_verified(
            &publication,
            episode_manifest
                .metadata_digest()
                .ok_or("episode metadata")?,
            1 << 20,
        )?,
    )?;
    Ok(Captured {
        agent,
        relay,
        principal,
        plan,
        supporting,
        root,
        learning_slot,
        proposal,
        proof_pointers,
        episode_rendering,
        original_resources: source.episode.resource_use_json,
    })
}

fn args(agent: &Agent, root: ContentDigest, extra: &[&str]) -> Vec<OsString> {
    let mut args = agent.args(
        "explain",
        &[
            "--session",
            &agent.session,
            "--learning-root",
            &root.to_text(),
            "--view",
            "forensic",
        ],
    );
    args.extend(extra.iter().map(OsString::from));
    args
}

fn mcp_arguments(agent: &Agent, root: ContentDigest, extra: &str) -> String {
    format!(
        r#"{{"session":{},"learning_root":{},"view":"forensic"{extra}}}"#,
        learning_quote(&agent.session),
        learning_quote(&root.to_text()),
    )
}

fn mcp_answer(
    agent: &Agent,
    principal: &str,
    root: ContentDigest,
    extra: &str,
    refused: bool,
) -> TestResult<String> {
    let reply = learning_mcp_tool_wire(
        agent,
        principal,
        "explain",
        &mcp_arguments(agent, root, extra),
    )?;
    assert_eq!(
        field(&reply, &["result", "isError"])?,
        &Value::Bool(refused)
    );
    let content = field(&reply, &["result", "content"])?
        .array()
        .ok_or("selected learning MCP content")?;
    assert_eq!(content.len(), 1);
    assert_eq!(text(&content[0], &["type"])?, "text");
    let body = text(&content[0], &["text"])?.to_owned();
    let (_, parsed) = agent.answer(None, &body)?;
    assert_eq!(text(&parsed, &["operationId"])?, "AOP-011");
    Ok(body)
}

fn proposition<'a>(value: &'a Value, id: &str) -> TestResult<&'a Value> {
    field(value, &["payload", "epistemic", "propositions"])?
        .array()
        .ok_or("selected learning propositions")?
        .iter()
        .find(|entry| text(entry, &["id"]).is_ok_and(|value| value == id))
        .ok_or_else(|| format!("missing exact proposition {id}").into())
}

fn assert_selected(value: &Value, captured: &Captured) -> TestResult {
    assert_eq!(text(value, &["operationId"])?, "AOP-011");
    assert_eq!(text(value, &["outcome"])?, "ok");
    assert_eq!(text(value, &["recoveryClass"])?, "safe_read_retry");
    assert_eq!(text(value, &["safeRetry"])?, "yes_same_request");
    assert_eq!(
        text(value, &["payloadSchema"])?,
        "fss.agent_cognitive_envelope.v1"
    );
    assert_eq!(text(value, &["sessionId"])?, captured.agent.session);
    assert_eq!(
        text(value, &["payload", "answerClass"])?,
        "learning_proposal"
    );
    assert_eq!(text(value, &["epistemicState"])?, "unknown");
    assert_eq!(text(value, &["completeness"])?, "partial");
    let statement = proposition(value, "learning:statement")?;
    assert_eq!(
        text(statement, &["statement"])?,
        captured.proposal.statement
    );
    assert_eq!(text(statement, &["state"])?, "unknown");
    assert_eq!(text(statement, &["provenance"])?, "remembered");
    let applicability = proposition(value, "learning:applicability")?;
    assert_eq!(
        text(applicability, &["statement"])?,
        captured.proposal.applicability_json
    );
    assert_eq!(text(applicability, &["state"])?, "unknown");
    assert_eq!(text(applicability, &["provenance"])?, "remembered");
    let status = parse(text(
        proposition(value, "learning:status")?,
        &["statement"],
    )?)?;
    assert_eq!(text(&status, &["promotionState"])?, "captured");
    assert_eq!(field(&status, &["confidenceNumerator"])?.integer(), Some(0));
    assert_eq!(field(&status, &["helpfulOutcomes"])?.integer(), Some(0));
    assert_eq!(field(&status, &["harmfulOutcomes"])?.integer(), Some(0));
    assert_eq!(
        field(&status, &["reviewAfterNs"])?.integer(),
        captured.proposal.review_after_ns,
    );
    assert_eq!(
        field(&status, &["expiryNs"])?.integer(),
        captured.proposal.expiry_ns,
        "an inspection must not renew the retained expiry",
    );
    for (field_name, count) in [
        (
            "supportingCount",
            captured.proposal.supporting_evidence.len(),
        ),
        (
            "contradictingCount",
            captured.proposal.contradicting_evidence.len(),
        ),
        (
            "counterexampleCount",
            captured.proposal.counterexamples.len(),
        ),
        (
            "validationCount",
            captured.proposal.required_validation.len(),
        ),
        ("revivalCount", captured.proposal.revival_conditions.len()),
    ] {
        assert_eq!(
            field(&status, &[field_name])?.integer(),
            Some(i128::try_from(count)?)
        );
    }
    for (prefix, expected) in [
        (
            "learning:supporting",
            &captured.proposal.supporting_evidence,
        ),
        (
            "learning:contradicting",
            &captured.proposal.contradicting_evidence,
        ),
        (
            "learning:counterexample",
            &captured.proposal.counterexamples,
        ),
        (
            "learning:validation",
            &captured.proposal.required_validation,
        ),
        ("learning:revival", &captured.proposal.revival_conditions),
    ] {
        for (index, expected) in expected.iter().enumerate() {
            assert_eq!(
                text(
                    proposition(value, &format!("{prefix}:{index}"))?,
                    &["statement"]
                )?,
                expected,
                "lost exact retained {prefix} entry {index}"
            );
        }
    }
    assert_eq!(
        text(proposition(value, "episode:resource-use")?, &["statement"])?,
        captured.original_resources
    );
    assert!(text(proposition(value, "experience:outcome")?, &["statement"])?.contains("cancelled"));
    let propositions = field(value, &["payload", "epistemic", "propositions"])?
        .array()
        .ok_or("selected learning epistemic propositions")?;
    for required in [
        "zero lower bounds do not mean zero actual cost",
        "do not establish causal effectiveness",
    ] {
        assert!(
            propositions.iter().any(|entry| {
                text(entry, &["state"]).is_ok_and(|state| state == "unknown")
                    && text(entry, &["statement"])
                        .is_ok_and(|statement| statement.contains(required))
            }),
            "lost mandatory uncertainty {required}"
        );
    }
    let proofs = texts(value, &["proofPointers"])?;
    let handles = field(value, &["payload", "evidenceHandles"])?
        .array()
        .ok_or("selected learning evidence handles")?;
    for (index, digest) in captured.proof_pointers.iter().take(6).enumerate() {
        assert!(
            proofs.contains(digest),
            "lost selected source proof {digest}"
        );
        let handle = handles
            .iter()
            .find(|handle| text(handle, &["objectDigest"]).is_ok_and(|value| value == digest))
            .ok_or_else(|| format!("missing exact selected source handle {digest}"))?;
        // The answer carries the actual experience and proposal metadata. Source-root
        // references alone must not claim their complete records have been hydrated.
        let hydration = if matches!(index, 1 | 2) { "H2" } else { "H0" };
        assert_eq!(text(handle, &["hydration"])?, hydration);
        assert_eq!(text(handle, &["availability"])?, "available");
        let allowed = texts(handle, &["allowedHydration"])?;
        assert!(allowed.iter().any(|value| value == hydration));
        assert!(
            allowed
                .iter()
                .all(|value| matches!(value.as_str(), "H0" | "H1" | "H2"))
        );
        let digest = ContentDigest::parse(digest)?;
        let bytes = fss_publication::read_verified(
            captured.agent.root.join("agent/publications"),
            digest,
            1 << 20,
        )?;
        assert_eq!(ContentDigest::sha256(&bytes), digest);
    }
    assert_eq!(
        field(value, &["payload", "coverage", "omittedCount"])?.integer(),
        Some(0)
    );
    assert!(texts(value, &["payload", "coverage", "omissionReasons"])?.is_empty());
    let authority = parse(text(
        proposition(value, "current:authority")?,
        &["statement"],
    )?)?;
    let remaining = u64::try_from(
        field(&authority, &["remainingSessionTokens"])?
            .integer()
            .ok_or("selected remaining session tokens")?,
    )?;
    let requested = field(value, &["payload", "budget", "requested", "tokens"])?;
    assert_eq!(requested.integer(), Some(16000));
    assert!(
        remaining >= 16000,
        "a forensic view must not enlarge the live session grant",
    );
    let consumed = u64::try_from(
        field(value, &["payload", "budget", "consumed", "tokens"])?
            .integer()
            .ok_or("selected consumed tokens")?,
    )?;
    assert!((1..=16000).contains(&consumed));
    assert_eq!(
        requested,
        field(value, &["budgets", "requested", "tokens"])?
    );
    Ok(())
}

fn assert_private_refusal(
    agent: &Agent,
    root: ContentDigest,
    extra: &[&str],
) -> TestResult<String> {
    let before = learning_tree(&agent.root, &[""])?;
    let (code, stdout) = run_fss(&args(agent, root, extra))?;
    let (code, result) = agent.answer(code, &stdout)?;
    assert_eq!(code, Some(5), "{stdout}");
    assert_eq!(text(&result, &["outcome"])?, "refused");
    assert!(!stdout.contains("PRIVATE_LEARNING_CANDIDATE_91c"));
    assert_eq!(learning_tree(&agent.root, &[""])?, before);
    Ok(stdout)
}

#[test]
fn selected_learning_explain_recovers_exact_details_without_request_or_full_inventory() -> TestResult
{
    let (directory, event) = corroborated_event("selected-learning-explain")?;
    let captured = capture(&directory, &event)?;
    let before = learning_tree(&captured.agent.root, &[""])?;
    // The request contains only the admitted session and exact retained publication root.
    // It does not reconstruct the old feedback statement, plan request, or source citations.
    let selected_args = args(
        &captured.agent,
        captured.root,
        &["--budget-tokens", "16000"],
    );
    let (code, first_stdout) = run_fss(&selected_args)?;
    let (code, first) = captured.agent.answer(code, &first_stdout)?;
    assert_eq!(code, Some(0), "{first_stdout}");
    assert_selected(&first, &captured)?;
    let wire_estimate = u64::try_from(first_stdout.trim_end().len().div_ceil(4))?;
    let reported_tokens = u64::try_from(
        field(&first, &["payload", "budget", "consumed", "tokens"])?
            .integer()
            .ok_or("selected full-wire token estimate")?,
    )?;
    assert_eq!(reported_tokens, wire_estimate);
    assert_eq!(learning_tree(&captured.agent.root, &[""])?, before);
    let (code, retry) = run_fss(&selected_args)?;
    assert_eq!(code, Some(0), "{retry}");
    assert_eq!(
        retry, first_stdout,
        "cold root-only inspection is deterministic"
    );
    let mcp = mcp_answer(
        &captured.agent,
        &captured.principal,
        captured.root,
        r#","budget_tokens":16000"#,
        false,
    )?;
    assert_eq!(
        mcp,
        first_stdout.trim_end(),
        "CLI and MCP share the exact native answer"
    );
    assert_eq!(learning_tree(&captured.agent.root, &[""])?, before);
    assert_eq!(captured.relay.connections(), 0);

    let tiny = assert_private_refusal(&captured.agent, captured.root, &["--budget-tokens", "1"])?;
    let tiny_mcp = mcp_answer(
        &captured.agent,
        &captured.principal,
        captured.root,
        r#","budget_tokens":1"#,
        true,
    )?;
    assert_eq!(tiny_mcp, tiny.trim_end());
    assert_eq!(learning_tree(&captured.agent.root, &[""])?, before);

    // Possession of a root grants neither another session nor another principal its contents.
    let other = open_with_budget(
        &directory,
        "An independent learning-review mission.",
        "64000",
    )?;
    assert_ne!(other.session, captured.agent.session);
    let foreign = assert_private_refusal(&other, captured.root, &[])?;
    let foreign_mcp = mcp_answer(&other, &captured.principal, captured.root, "", true)?;
    assert_eq!(foreign_mcp, foreign.trim_end());
    let denied = assert_private_refusal(
        &captured.agent,
        captured.root,
        &["--principal", "principal:other-learning-reviewer"],
    )?;
    let denied_mcp = mcp_answer(
        &captured.agent,
        "principal:other-learning-reviewer",
        captured.root,
        "",
        true,
    )?;
    assert_eq!(denied_mcp, denied.trim_end());

    for rejected in [
        ContentDigest::sha256(b"a learning publication that does not exist"),
        ContentDigest::parse(&captured.proof_pointers[5])?,
    ] {
        assert_private_refusal(&captured.agent, rejected, &[])?;
        mcp_answer(&captured.agent, &captured.principal, rejected, "", true)?;
    }

    // Verified but orphaned or indeterminate objects are not an admitted visible capture.
    let publications = captured.agent.root.join("agent/publications");
    let roots = publications.join(fss_publication::LOCAL_ROOTS_DIR);
    let selected_slot = roots.join(format!(
        "{}{}",
        captured.learning_slot,
        fss_publication::ROOT_RECORD_SUFFIX,
    ));
    let slot_record = fs::read(&selected_slot)?;
    fs::remove_file(&selected_slot)?;
    let orphaned = learning_tree(&captured.agent.root, &[""])?;
    assert_private_refusal(&captured.agent, captured.root, &[])?;
    mcp_answer(
        &captured.agent,
        &captured.principal,
        captured.root,
        "",
        true,
    )?;
    assert_eq!(learning_tree(&captured.agent.root, &[""])?, orphaned);
    fs::write(&selected_slot, &slot_record)?;
    let indeterminate_slot = roots.join(format!(
        "{}{}{}",
        captured.learning_slot,
        fss_publication::ROOT_RECORD_SUFFIX,
        fss_publication::ROOT_INDETERMINATE_SUFFIX,
    ));
    let tombstones = publications.join(fss_publication::LOCAL_TOMBSTONES_DIR);
    fs::create_dir_all(&tombstones)?;
    let indeterminate_tombstone = tombstones.join(format!(
        "{}{}.indeterminate",
        captured.proof_pointers[2].replace(':', "-"),
        fss_publication::TOMBSTONE_RECORD_SUFFIX,
    ));
    for marker in [indeterminate_slot, indeterminate_tombstone] {
        assert!(!marker.exists());
        fs::write(&marker, b"selected custody is indeterminate\n")?;
        let marked = learning_tree(&captured.agent.root, &[""])?;
        assert_private_refusal(&captured.agent, captured.root, &[])?;
        mcp_answer(
            &captured.agent,
            &captured.principal,
            captured.root,
            "",
            true,
        )?;
        assert_eq!(learning_tree(&captured.agent.root, &[""])?, marked);
        fs::remove_file(marker)?;
    }

    // Hash-verified exact children are mandatory even when the top-level root and slot remain.
    for (digest, missing) in [
        (captured.episode_rendering, true),
        (ContentDigest::parse(&captured.proof_pointers[2])?, false),
    ] {
        let name = digest.to_text();
        let path = publications
            .join("spool/objects")
            .join(name.strip_prefix("sha256:").ok_or("selected object name")?);
        let original = fs::read(&path)?;
        if missing {
            fs::remove_file(&path)?;
        } else {
            let mut damaged = original.clone();
            *damaged.last_mut().ok_or("empty selected object")? ^= 1;
            fs::write(&path, damaged)?;
        }
        let damaged = learning_tree(&captured.agent.root, &[""])?;
        assert_private_refusal(&captured.agent, captured.root, &[])?;
        mcp_answer(
            &captured.agent,
            &captured.principal,
            captured.root,
            "",
            true,
        )?;
        assert_eq!(learning_tree(&captured.agent.root, &[""])?, damaged);
        fs::write(path, original)?;
    }

    // Targeted custody must not enumerate or decode unrelated learning publications.
    let unrelated = roots.join("learning-unrelated-selected-read.root");
    assert!(!unrelated.exists());
    fs::write(&unrelated, b"unrelated malformed retained root record\n")?;
    let unrelated_before = learning_tree(&captured.agent.root, &[""])?;
    let (code, selected_stdout) = run_fss(&selected_args)?;
    let (code, selected) = captured.agent.answer(code, &selected_stdout)?;
    assert_eq!(code, Some(0), "{selected_stdout}");
    assert_selected(&selected, &captured)?;
    assert_eq!(
        mcp_answer(
            &captured.agent,
            &captured.principal,
            captured.root,
            r#","budget_tokens":16000"#,
            false,
        )?,
        selected_stdout.trim_end(),
    );
    assert_eq!(
        learning_tree(&captured.agent.root, &[""])?,
        unrelated_before
    );
    fs::remove_file(unrelated)?;

    check_conflicting_selectors(&directory, &captured, &event)?;

    // A bounded sequence of real captures reaches the actual protected-context ceiling.
    // No test assumes that sixteen captures can fit the EpistemicMap's 3000-token view.
    let mut full_orientation_refused = false;
    for index in 0..fss_reference::deployment_session::learning::MAX_CAPTURED_LEARNING {
        let statement = format!(
            "Additional advisory capture {index}; causal effectiveness remains unvalidated."
        );
        let (code, stdout) = run_fss(&learning_args(
            &captured.agent,
            &captured.plan,
            &captured.supporting,
            &statement,
        ))?;
        let (_, response) = captured.agent.answer(code, &stdout)?;
        let (orientation_code, orientation) = captured.agent.run(
            "orient",
            &[
                "--session",
                &captured.agent.session,
                "--view",
                "epistemic_map",
            ],
        )?;
        if orientation_code == Some(5) {
            assert_eq!(text(&orientation, &["outcome"])?, "refused");
            full_orientation_refused = true;
            break;
        }
        assert_eq!(orientation_code, Some(0), "{orientation:?}");
        assert_eq!(code, Some(0), "{response:?}");
    }
    assert!(
        full_orientation_refused,
        "fixture never exceeded complete orientation's protected budget"
    );
    let after_growth = learning_tree(&captured.agent.root, &[""])?;
    let (code, selected_stdout) = run_fss(&selected_args)?;
    let (code, selected) = captured.agent.answer(code, &selected_stdout)?;
    assert_eq!(code, Some(0), "{selected_stdout}");
    assert_selected(&selected, &captured)?;
    assert_eq!(
        mcp_answer(
            &captured.agent,
            &captured.principal,
            captured.root,
            r#","budget_tokens":16000"#,
            false,
        )?,
        selected_stdout.trim_end(),
    );
    assert_eq!(learning_tree(&captured.agent.root, &[""])?, after_growth);
    assert_eq!(captured.relay.connections(), 0);
    Ok(())
}

fn check_conflicting_selectors(
    directory: &OwnedDirectory,
    captured: &Captured,
    event: &str,
) -> TestResult {
    let before = learning_tree(&captured.agent.root, &[""])?;
    for suffix in [
        r#","event_id":"event:foreign""#,
        r#","at":"anchor:foreign""#,
        r#","custody":"yes""#,
        r#","fusion_policy":"sha256:foreign""#,
        r#","score_calibration":"sha256:foreign""#,
        r#","root":"/outside/deployment""#,
        r#","principal":"principal:other""#,
        r#","activate":true"#,
    ] {
        let reply = learning_mcp_tool_wire(
            &captured.agent,
            &captured.principal,
            "explain",
            &mcp_arguments(&captured.agent, captured.root, suffix),
        )?;
        assert_eq!(field(&reply, &["error", "code"])?.integer(), Some(-32602));
        assert_eq!(learning_tree(&captured.agent.root, &[""])?, before);
    }
    for arguments in [
        format!(
            r#"{{"learning_root":{},"view":"forensic"}}"#,
            learning_quote(&captured.root.to_text())
        ),
        format!(
            r#"{{"session":{},"view":"forensic"}}"#,
            learning_quote(&captured.agent.session)
        ),
        format!(
            r#"{{"session":{},"learning_root":null,"view":"forensic"}}"#,
            learning_quote(&captured.agent.session)
        ),
    ] {
        let reply =
            learning_mcp_tool_wire(&captured.agent, &captured.principal, "explain", &arguments)?;
        assert_eq!(field(&reply, &["error", "code"])?.integer(), Some(-32602));
        assert_eq!(learning_tree(&captured.agent.root, &[""])?, before);
    }
    // Point the launcher at a nonexistent path: selector conflicts must remain parse errors,
    // before a deployment read or attempted creation can obscure their classification.
    let missing_root = directory.0.join("unopened-selected-learning-root");
    let invalid_agent = Agent {
        root: missing_root.clone(),
        scratch: captured.agent.scratch.clone(),
        session: captured.agent.session.clone(),
    };
    for extra in [
        vec!["--event-id", event],
        vec!["--at", "anchor:foreign"],
        vec!["--custody", "yes"],
        vec!["--fusion-policy", "sha256:foreign"],
        vec!["--score-calibration", "sha256:foreign"],
    ] {
        let (code, _) = run_fss(&args(&invalid_agent, captured.root, &extra))?;
        assert_eq!(
            code,
            Some(2),
            "conflicting selected-learning request must fail parsing"
        );
        assert!(!missing_root.exists());
        assert_eq!(learning_tree(&captured.agent.root, &[""])?, before);
    }
    for missing_selector in [
        invalid_agent.args("explain", &["--learning-root", &captured.root.to_text()]),
        invalid_agent.args("explain", &["--session", &captured.agent.session]),
    ] {
        let (code, _) = run_fss(&missing_selector)?;
        assert_eq!(
            code,
            Some(2),
            "both selected-learning identity fields are required"
        );
        assert!(!missing_root.exists());
        assert_eq!(learning_tree(&captured.agent.root, &[""])?, before);
    }
    assert_eq!(captured.relay.connections(), 0);
    Ok(())
}
