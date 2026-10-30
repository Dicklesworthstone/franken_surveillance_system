#![forbid(unsafe_code)]
//! Real native source → exact case citation → cold CLI/MCP metadata recovery.

use super::*;

struct Target {
    case: &'static str,
    expected: String,
    hypothesis: String,
}

fn case_command(
    f: &Fixture,
    session: &str,
    transition: &str,
    flags: &[(&str, &str)],
) -> TestResult<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss"));
    command
        .args(["investigate", "--json", "--root"])
        .arg(&f.root)
        .args([
            "--session",
            session,
            "--principal",
            PRINCIPAL,
            "--transition",
            transition,
        ]);
    for (key, value) in flags {
        command.args([key, value]);
    }
    Ok(command.output()?)
}

fn target(f: &Fixture, session: &str, request: &Value, case: &'static str) -> TestResult<Target> {
    let hypothesis = text(field(request, "plan")?, "hypothesis_id")?.to_owned();
    let draft = object(&[
        ("caseId", string(case)),
        (
            "question",
            string("Does retained native class evidence support the configured hypothesis?"),
        ),
        (
            "decisionInformed",
            string("Choose whether more independent evidence is needed"),
        ),
        (
            "hypotheses",
            format!(
                "[{},{}]",
                object(&[
                    ("hypothesisId", string(&hypothesis)),
                    ("description", string("The configured class is supported"))
                ]),
                object(&[
                    ("hypothesisId", string("hypothesis:alternative")),
                    (
                        "description",
                        string("The detector observation has another explanation")
                    )
                ])
            ),
        ),
        ("probes", "[\"agent-probe\"]".to_owned()),
        (
            "stopRules",
            "[\"Review independent evidence without automatic assessment\"]".to_owned(),
        ),
        ("decisionWindowNs", "3600000000000".to_owned()),
    ]);
    let path = f
        .directory
        .0
        .join(format!("{}.json", case.replace(':', "-")));
    fs::write(&path, draft)?;
    let opened = case_command(
        f,
        session,
        "open",
        &[("--case-file", path.to_str().ok_or("case path")?)],
    )?;
    success(&opened);
    let opened = report(&opened)?;
    let expected = text(payload(&opened)?, "revisionDigest")?;
    let active = case_command(
        f,
        session,
        "activate",
        &[("--case", case), ("--expected", expected)],
    )?;
    success(&active);
    let active = report(&active)?;
    Ok(Target {
        case,
        expected: text(payload(&active)?, "revisionDigest")?.to_owned(),
        hypothesis,
    })
}

fn linked(
    f: &Fixture,
    session: &str,
    target: &Target,
    state: ContentDigest,
    view: &str,
) -> TestResult<Output> {
    cli(
        f,
        session,
        "probe",
        &[
            ("--case", target.case),
            ("--expected", &target.expected),
            ("--hypothesis", &target.hypothesis),
            ("--side", "support"),
            ("--subscription-state", &state.to_text()),
            ("--view", view),
        ],
    )
}

fn lookup(f: &Fixture, session: &str, target: &Target) -> TestResult<Value> {
    tool(
        f,
        session,
        "probe-citation",
        &[
            ("case", string(target.case)),
            ("expected", string(&target.expected)),
            ("hypothesis", string(&target.hypothesis)),
            ("side", string("support")),
        ],
        false,
    )
}

fn case_head(f: &Fixture, session: &str, target: &Target) -> TestResult<Value> {
    let output = case_command(f, session, "inspect", &[("--case", target.case)])?;
    success(&output);
    report(&output)
}

fn citation_id(answer: &Value) -> TestResult<String> {
    let handle = field(payload(answer)?, "evidenceHandles")?
        .array()
        .ok_or("handles")?
        .iter()
        .find(|handle| {
            text(handle, "kind").is_ok_and(|kind| kind == "retained_probe_case_citation")
        })
        .ok_or("exact case citation handle")?;
    Ok(text(handle, "objectDigest")?.to_owned())
}

fn assert_unassessed_case(answer: &Value, target: &Target, evidence: ContentDigest) -> TestResult {
    let hypotheses = field(payload(answer)?, "hypotheses")?
        .array()
        .ok_or("hypotheses")?;
    assert_eq!(hypotheses.len(), 2);
    for hypothesis in hypotheses {
        assert_eq!(
            text(hypothesis, "disposition")?,
            "live",
            "probe silently assessed a hypothesis"
        );
        assert_eq!(text(hypothesis, "epistemicState")?, "unknown");
        if text(hypothesis, "hypothesisId")? == target.hypothesis {
            assert!(
                field(hypothesis, "evidence")?
                    .array()
                    .ok_or("evidence")?
                    .contains(&Value::Text(evidence.to_text()))
            );
        }
    }
    Ok(())
}

#[test]
fn exact_case_link_recovers_across_cli_mcp_after_ack_and_later_case_revision() -> TestResult {
    let f = Fixture::new("case-probe-cold", 1)?;
    let request = f.discovery(&[0])?;
    let session = open_session(&f)?;
    success(&poll(
        &f,
        &request,
        &session,
        "agent-probe",
        8,
        Some(("--schedule", "yes")),
    )?);
    let target = target(&f, &session, &request, "case:retained-probe")?;
    let before = state(&f, "agent-probe")?;
    let canonical = canonical_inventory(&f)?;
    let before_tokens = spent(&f, &session)?;
    tool(
        &f,
        &session,
        "probe",
        &[
            ("case", string(target.case)),
            ("expected", string(&target.expected)),
            ("hypothesis", string(&target.hypothesis)),
            ("side", string("support")),
            ("subscription_state", string(&before.digest().to_text())),
        ],
        true,
    )?;
    assert_eq!(
        state(&f, "agent-probe")?,
        before,
        "notification started linked native work"
    );
    assert_eq!(spent(&f, &session)?, before_tokens);
    assert_eq!(
        text(
            payload(&case_head(&f, &session, &target)?)?,
            "revisionDigest"
        )?,
        target.expected,
        "notification linked a case result"
    );
    let output = linked(&f, &session, &target, before.digest(), "forensic")?;
    success(&output);
    let answer = report(&output)?;
    assert_v2_contract(&f, &answer)?;
    let citation = citation_id(&answer)?;
    let after = state(&f, "agent-probe")?;
    assert_eq!(after.attempts_reserved(), 1);
    let pending = after.pending().ok_or("native report remains pending")?;
    let receipt = pending.receipt();
    assert_eq!(after.last_acknowledged(), None);
    let case = case_head(&f, &session, &target)?;
    assert_unassessed_case(&case, &target, pending.payload_digest())?;
    assert_eq!(
        text(payload(&case)?, "predecessorRevision")?,
        target.expected
    );
    assert!(has_proposition(
        &answer,
        "probe:case-linked",
        text(payload(&case)?, "revisionDigest")?
    )?);

    // An unchanged linked retry is fenced before another source attempt or case revision.
    let retried = linked(&f, &session, &target, before.digest(), "forensic")?;
    assert!(!retried.status.success());
    assert_eq!(state(&f, "agent-probe")?, after);
    assert_eq!(
        text(
            payload(&case_head(&f, &session, &target)?)?,
            "revisionDigest"
        )?,
        text(payload(&case)?, "revisionDigest")?
    );

    let recovered = lookup(&f, &session, &target)?;
    assert_v2_contract(&f, &recovered)?;
    assert_eq!(citation_id(&recovered)?, citation);
    assert_eq!(
        state(&f, "agent-probe")?,
        after,
        "historical lookup repeated source work"
    );
    assert!(has_proposition(
        &recovered,
        "probe:case-linked",
        "current delivery status is not established"
    )?);
    assert!(!encode(&recovered).contains("existing owned retained-source subscription"));

    success(&cli(
        &f,
        &session,
        "probe-ack",
        &[("--receipt", &receipt.to_text()), ("--view", "forensic")],
    )?);
    let acknowledged = state(&f, "agent-probe")?;
    assert_eq!(acknowledged.last_acknowledged(), Some(receipt));
    assert!(acknowledged.pending().is_none());
    let reason = ContentDigest::sha256(b"explicitly retain competing case hypotheses").to_text();
    let later = case_command(
        &f,
        &session,
        "set-state",
        &[
            ("--case", target.case),
            ("--expected", text(payload(&case)?, "revisionDigest")?),
            ("--state", "awaiting_evidence"),
            ("--reason", &reason),
        ],
    )?;
    success(&later);
    let recovered = lookup(&f, &session, &target)?;
    assert_eq!(citation_id(&recovered)?, citation);
    assert!(has_proposition(
        &recovered,
        "probe:case-linked",
        "Report was pending at citation time"
    )?);
    assert_eq!(state(&f, "agent-probe")?, acknowledged);
    assert_eq!(canonical_inventory(&f)?, canonical);
    Ok(())
}

#[test]
fn published_but_unlinked_work_requires_new_explicit_state_after_zero_work_lookup() -> TestResult {
    let f = Fixture::new("case-probe-unlinked", 1)?;
    let request = f.discovery(&[0])?;
    let session = open_session(&f)?;
    success(&poll(
        &f,
        &request,
        &session,
        "agent-probe",
        8,
        Some(("--schedule", "yes")),
    )?);
    let target = target(&f, &session, &request, "case:interrupted-probe")?;
    let original = state(&f, "agent-probe")?;
    // Model the real crash boundary: native owner published, no case-citation append occurred.
    success(&poll(&f, &request, &session, "agent-probe", 8, None)?);
    let pending = state(&f, "agent-probe")?;
    assert_eq!(pending.attempts_reserved(), 1);
    assert!(
        !linked(&f, &session, &target, original.digest(), "forensic")?
            .status
            .success()
    );
    assert_eq!(state(&f, "agent-probe")?, pending);
    let absent = lookup(&f, &session, &target)?;
    assert!(has_proposition(
        &absent,
        "probe:case-citation-absent",
        "does not prove no source attempt"
    )?);
    assert_eq!(state(&f, "agent-probe")?, pending);
    assert_eq!(
        text(
            payload(&case_head(&f, &session, &target)?)?,
            "revisionDigest"
        )?,
        target.expected
    );

    // A new explicit state opts into one bounded revalidation of the same retained result.
    let chosen = pending.digest();
    let linked_output = linked(&f, &session, &target, chosen, "forensic")?;
    success(&linked_output);
    let after = state(&f, "agent-probe")?;
    assert_eq!(after.pending(), pending.pending());
    assert_eq!(after.attempts_reserved(), 2);
    assert_eq!(after.last_acknowledged(), None);
    assert_unassessed_case(
        &case_head(&f, &session, &target)?,
        &target,
        pending.pending().ok_or("pending")?.payload_digest(),
    )?;
    Ok(())
}

#[test]
fn case_view_overflow_retains_case_link_pending_receipt_and_recovers_without_source_work()
-> TestResult {
    let f = Fixture::new("case-probe-overflow", 1)?;
    let request = f.discovery(&[0])?;
    let session = open_session(&f)?;
    success(&poll(
        &f,
        &request,
        &session,
        "agent-probe",
        8,
        Some(("--schedule", "yes")),
    )?);
    let target = target(&f, &session, &request, "case:bounded-probe")?;
    let original = state(&f, "agent-probe")?;
    let before_tokens = spent(&f, &session)?;
    let output = linked(&f, &session, &target, original.digest(), "case")?;
    assert!(!output.status.success());
    let answer = report(&output)?;
    assert_eq!(text(&answer, "outcome")?, "partial");
    assert_eq!(text(&answer, "effectiveViewId")?, "AVIEW-003");
    assert_schema(&f, "agent_response_envelope.v1.json", &answer)?;
    assert!(
        (encode(&answer).len() as u64).div_ceil(4) <= 5_000,
        "case-link refusal escaped the selected Case wire bound"
    );
    let retained = state(&f, "agent-probe")?;
    assert_eq!(retained.attempts_reserved(), 1);
    assert_eq!(retained.last_acknowledged(), None);
    let pending = retained.pending().ok_or("retained native report")?;
    assert_eq!(
        spent(&f, &session)?,
        before_tokens,
        "incomplete complete projection was charged"
    );
    let head = case_head(&f, &session, &target)?;
    assert_unassessed_case(&head, &target, pending.payload_digest())?;
    assert!(
        encode(&answer).contains(text(payload(&head)?, "revisionDigest")?),
        "definite case revision was lost from refusal"
    );
    assert!(
        encode(&answer).contains(&pending.receipt().to_text()),
        "native pending receipt was lost from refusal"
    );
    let recovered = lookup(&f, &session, &target)?;
    assert_v2_contract(&f, &recovered)?;
    assert!(has_proposition(
        &recovered,
        "probe:case-linked",
        text(payload(&head)?, "revisionDigest")?
    )?);
    assert_eq!(state(&f, "agent-probe")?, retained);
    Ok(())
}

#[test]
fn stale_case_or_hypothesis_mapping_refuses_before_any_native_attempt() -> TestResult {
    let f = Fixture::new("case-probe-preflight", 1)?;
    let request = f.discovery(&[0])?;
    let session = open_session(&f)?;
    success(&poll(
        &f,
        &request,
        &session,
        "agent-probe",
        8,
        Some(("--schedule", "yes")),
    )?);
    let mut target = target(&f, &session, &request, "case:probe-preflight")?;
    let original = state(&f, "agent-probe")?;
    let correct = target.expected.clone();
    target.expected = ContentDigest::sha256(b"stale case predecessor").to_text();
    assert!(
        !linked(&f, &session, &target, original.digest(), "forensic")?
            .status
            .success()
    );
    target.expected = correct;
    target.hypothesis = "hypothesis:alternative".to_owned();
    assert!(
        !linked(&f, &session, &target, original.digest(), "forensic")?
            .status
            .success()
    );
    assert_eq!(state(&f, "agent-probe")?, original);
    assert_eq!(original.attempts_reserved(), 0);
    assert!(original.pending().is_none());
    Ok(())
}
